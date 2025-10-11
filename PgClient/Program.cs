// See https://aka.ms/new-console-template for more information
using System.Buffers.Binary;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using PgClient;

Console.WriteLine("Postgreswl cinet!");

string host = "localhost";
int port = 5432;
string user = "postgres";
string password = "postgres";
string database = "movie";

using var client = new TcpClient(host, port);
using var stream = client.GetStream();
Console.WriteLine("Connection to db...");

SendStartUpMessage(stream, user, password, database);
while (true)
{
    var msgType = (char)stream.ReadByte();
    int length = Helper.ReadInt32(stream) - 4;

    if (msgType == 'R') // Authentication
    {
        int authType = Helper.ReadInt32(stream);
        if (authType == 10) // SCRAM-SHA-256
        {
            Console.WriteLine("🔐 Server requests SCRAM-SHA-256 auth.");
            byte[] mechanisms = new byte[length];
            stream.Read(mechanisms, 0, length);
            string mechString = Encoding.UTF8.GetString(mechanisms).TrimEnd('\0');
            Console.WriteLine("db auth stream - ", mechString);
            if (!mechString.Contains("SCRAM-SHA-256"))
                throw new Exception("SCRAM-SHA-256 not supported by server.");

            SendSCRAMInitial(stream, user, password);
        }
        else if (authType == 3)
        {
            Console.WriteLine("Server requests cleartext password.");
            SendPasswordMessage(stream, password);
        }
        else if (authType == 5)
        {
            Console.WriteLine("Server requests MD5 password (not implemented yet).");
            return;
        }
        else if (authType == 0)
        {
            Console.WriteLine("Authentication successful!");
        }
        else
        {
            Console.WriteLine($"Unknown auth type: {authType}");
        }
        length -= 4;
        if (length > 0) stream.Read(new byte[length], 0, length);
    }
    else if (msgType == 'S')
    {
        Helper.SkipMessage(stream, length); // ParameterStatus
    }
    else if (msgType == 'K')
    {
        Helper.SkipMessage(stream, length); // BackendKeyData
    }
    else if (msgType == 'Z')
    {
        Helper.SkipMessage(stream, length);
        Console.WriteLine("Server ready for query!");
        break;
    }
    else
    {
        Helper.SkipMessage(stream, length);
    }
}

// Step 3: Send a query
string query = "SELECT * FROM Movie;";
SendQuery(stream, query);
Console.WriteLine("Query sent.");

// Step 4: Read response
ReadResponse(stream);


static void SendSCRAMInitial(NetworkStream stream, string username, string password)
{
    // Generate client nonce
    byte[] nonceBytes = new byte[18];
    RandomNumberGenerator.Fill(nonceBytes);
    string nonce = Convert.ToBase64String(nonceBytes);

    // Client-first-message
    string clientFirstMessageBare = $"n={username},r={nonce}";
    string clientFirstMessage = "n,," + clientFirstMessageBare;

    byte[] clientFirstBytes = Encoding.UTF8.GetBytes(clientFirstMessage);
    byte[] mechanismBytes = Encoding.UTF8.GetBytes("SCRAM-SHA-256\0");

    using var ms = new MemoryStream();
    using var writer = new BinaryWriter(ms);
    writer.Write((byte)'p'); // SASLInitialResponse
    int totalLen = 4 + mechanismBytes.Length + 4 + clientFirstBytes.Length;
    WriteInt32BE(writer, totalLen);
    writer.Write(mechanismBytes); // mechanism
    WriteInt32BE(writer, clientFirstBytes.Length);
    writer.Write(clientFirstBytes);
    stream.Write(ms.ToArray(), 0, (int)ms.Length);

    // Read server-first-message
    char type = (char)stream.ReadByte();
    int length = ReadInt32BE(stream);
    byte[] payload = new byte[length];
    stream.Read(payload, 0, length);
    string serverFirst = Encoding.UTF8.GetString(payload);

    // Parse server nonce, salt, iterations
    var parts = serverFirst.Split(',');
    string serverNonce = parts[0].Substring(2);
    string salt = parts[1].Substring(2);
    int iterations = int.Parse(parts[2].Substring(2));

    // Client-final-message
    string channelBinding = "c=biws";
    string nonceFinal = $"r={serverNonce}";
    string authMessage = clientFirstMessageBare + "," + serverFirst + "," + channelBinding + "," + nonceFinal;

    byte[] saltedPassword = PBKDF2SHA256(password, Convert.FromBase64String(salt), iterations);
    byte[] clientKey = HMACSHA256(saltedPassword, "Client Key");
    byte[] storedKey = SHA256Hash(clientKey);
    byte[] clientSignature = HMACSHA256(storedKey, authMessage);
    byte[] clientProofBytes = XOR(clientKey, clientSignature);
    string clientProof = Convert.ToBase64String(clientProofBytes);

    string clientFinalMessage = $"{channelBinding},{nonceFinal},p={clientProof}";

    // Send client-final-message
    byte[] finalBytes = Encoding.UTF8.GetBytes(clientFinalMessage);
    using var ms2 = new MemoryStream();
    using var writer2 = new BinaryWriter(ms2);
    writer2.Write((byte)'p');
    WriteInt32BE(writer2, finalBytes.Length + 4 + 1);
    writer2.Write(finalBytes);
    stream.Write(ms2.ToArray(), 0, (int)ms2.Length);

    // Server-final-message
    type = (char)stream.ReadByte();
    length = ReadInt32BE(stream) - 4;
    SkipBytes(stream, length);

    Console.WriteLine("✅ SCRAM-SHA-256 authentication complete.");
}

// ======== PBKDF2 / HMAC / helpers ========

static byte[] PBKDF2SHA256(string password, byte[] salt, int iterations)
{
    using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
    return pbkdf2.GetBytes(32);
}

static byte[] HMACSHA256(byte[] key, string message)
{
    using var hmac = new HMACSHA256(key);
    return hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
}

static byte[] SHA256Hash(byte[] input)
{
    using var sha = SHA256.Create();
    return sha.ComputeHash(input);
}

static byte[] XOR(byte[] a, byte[] b)
{
    byte[] result = new byte[a.Length];
    for (int i = 0; i < a.Length; i++)
        result[i] = (byte)(a[i] ^ b[i]);
    return result;
}


static void SendStartUpMessage(NetworkStream stream, string user, string password, string database)
{
    using var ms = new MemoryStream();
    using var writer = new BinaryWriter(ms, Encoding.UTF8);

    writer.Write(Helper.ToBigEndian(196608)); /// protocol 3.0 (0x00030000)
    Helper.WriteCString(writer, "user");
    Helper.WriteCString(writer, user);
    Helper.WriteCString(writer, "database");
    Helper.WriteCString(writer, database);
    writer.Write((byte)0);  /// terminator 

    byte[] payload = ms.ToArray();
    int length = payload.Length + 4;

    using var final = new MemoryStream();
    using var finalWriter = new BinaryWriter(final);
    finalWriter.Write(Helper.ToBigEndian(length));
    finalWriter.Write(payload);

    byte[] msg = final.ToArray();
    stream.Write(msg, 0, msg.Length);
}

static void SendPasswordMessage(NetworkStream stream, string password)
{
    using var ms = new MemoryStream();
    using var writer = new BinaryWriter(ms, Encoding.UTF8);
    Helper.WriteCString(writer, password);

    byte[] payload = ms.ToArray();
    int length = payload.Length + 4 + 1;

    using var final = new MemoryStream();
    using var finalWriter = new BinaryWriter(final);
    finalWriter.Write((byte)'p');
    finalWriter.Write(Helper.ToBigEndian(length));
    finalWriter.Write(payload);

    byte[] msg = final.ToArray();
    stream.Write(msg, 0, msg.Length);
}

static void SendQuery(NetworkStream stream, string sql)
{
    byte[] queryBytes = Encoding.UTF8.GetBytes(sql + "\0");
    int length = queryBytes.Length + 4 + 1;

    using var ms = new MemoryStream();
    using var writer = new BinaryWriter(ms);
    writer.Write((byte)'Q');
    writer.Write(Helper.ToBigEndian(length));
    writer.Write(queryBytes);

    byte[] msg = ms.ToArray();
    stream.Write(msg, 0, msg.Length);
}

static void ReadResponse(NetworkStream stream)
{
    while (true)
    {
        int typeInt = stream.ReadByte();
        if (typeInt == -1) break;

        char msgType = (char)typeInt;
        int length = Helper.ReadInt32(stream) - 4;

        if (msgType == 'T') // RowDescription
        {
            int fieldCount = Helper.ReadInt16(stream);
            Console.WriteLine($"RowDescription: {fieldCount} fields");
            Helper.SkipMessage(stream, length - 2);
        }
        else if (msgType == 'D') // DataRow
        {
            int columnCount = Helper.ReadInt16(stream);
            Console.Write("Row: ");
            for (int i = 0; i < columnCount; i++)
            {
                int colLen = Helper.ReadInt32(stream);
                byte[] colData = new byte[colLen];
                stream.Read(colData, 0, colLen);
                string value = Encoding.UTF8.GetString(colData);
                Console.Write(value + (i < columnCount - 1 ? ", " : ""));
            }
            Console.WriteLine();
        }
        else if (msgType == 'C') // CommandComplete
        {
            string msg = Helper.ReadCString(stream);
            Console.WriteLine("Command complete: " + msg);
        }
        else if (msgType == 'Z') // ReadyForQuery
        {
            Helper.SkipMessage(stream, length);
            Console.WriteLine("Ready for next query!");
            break;
        }
        else
        {
            Helper.SkipMessage(stream, length);
        }
    }
}

static void WriteCString(BinaryWriter writer, string value)
{
    writer.Write(Encoding.UTF8.GetBytes(value));
    writer.Write((byte)0);
}

static void SkipBytes(NetworkStream stream, int length)
{
    byte[] buf = new byte[length];
    stream.Read(buf, 0, length);
}

static int ReadInt32BE(Stream stream)
{
    Span<byte> buf = stackalloc byte[4];
    stream.Read(buf);
    return BinaryPrimitives.ReadInt32BigEndian(buf);
}

static short ReadInt16BE(Stream stream)
{
    Span<byte> buf = stackalloc byte[2];
    stream.Read(buf);
    return BinaryPrimitives.ReadInt16BigEndian(buf);
}

static void WriteInt32BE(BinaryWriter writer, int value)
{
    Span<byte> buf = stackalloc byte[4];
    BinaryPrimitives.WriteInt32BigEndian(buf, value);
    writer.Write(buf);
}

static void WriteInt16BE(BinaryWriter writer, short value)
{
    Span<byte> buf = stackalloc byte[2];
    BinaryPrimitives.WriteInt16BigEndian(buf, value);
    writer.Write(buf);
}

static string ReadCString(Stream stream)
{
    var sb = new StringBuilder();
    int b;
    while ((b = stream.ReadByte()) > 0)
        sb.Append((char)b);
    return sb.ToString();
}
