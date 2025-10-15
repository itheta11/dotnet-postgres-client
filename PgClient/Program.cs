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

string clientFirstBare = null;
string clientNonce = null;
byte[] saltedPassword = null;
string authMessage = null;
var authenticated = false;
while (true)
{
    var (msgType, payload) = ReadMessage(stream);
    int length = Helper.ReadInt32(stream) - 4;

    if (msgType == 'R') // Authentication
    {
        if (payload.Length < 4) throw new Exception("Authentication message too short.");
        int authType = ReadInt32FromBuffer(payload, 0);
        var rest = SubArray(payload, 4, Math.Max(0, payload.Length - 4)); 
        if (authType == 10) // SCRAM-SHA-256
        {
            Console.WriteLine("🔐 Server requests SCRAM-SHA-256 auth.");
            byte[] mechanisms = new byte[length];
            stream.Read(mechanisms, 0, length);
            string mechString = Encoding.UTF8.GetString(mechanisms).TrimEnd('\0');
            Console.WriteLine("db auth stream - ", mechString);
            if (!mechString.Contains("SCRAM-SHA-256"))
                throw new Exception("SCRAM-SHA-256 not supported by server.");

            clientNonce = SendSCRAMInitial(stream, user, password);
            Console.WriteLine("Sent SASLInitialResponse.");

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
        else if (authType == 11)
        {
            string serverFirst = Encoding.UTF8.GetString(rest);
            // serverFirst should be like: r=<nonce>,s=<base64salt>,i=<iterations>
            // Compute salted password and send SASLResponse (client-final-message)
            saltedPassword = ComputeSaltedPassword(password, serverFirst, out authMessage, clientFirstBare, clientNonce);
            SendSaslResponse(stream, authMessage, saltedPassword);
            Console.WriteLine("Sent SASLResponse (client-final).");
        }
        else if (authType == 12)
        {
            string serverFinal = Encoding.UTF8.GetString(rest);
            // Usually contains v=<serverSignature> or an error.
            ValidateServerFinal(serverFinal, saltedPassword, authMessage);
            Console.WriteLine("Received server-final-message.");
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


static byte[] ComputeSaltedPassword(string password, string serverFirst, out string authMessage, string clientFirstBare, string clientNonce)
{
    // parse serverFirst: "r=<nonce>,s=<salt>,i=<iterations>"
    string serverNonce = null;
    string saltB64 = null;
    int iterations = 0;

    var parts = serverFirst.Split(',');
    foreach (var p in parts)
    {
        if (p.StartsWith("r=")) serverNonce = p.Substring(2);
        else if (p.StartsWith("s=")) saltB64 = p.Substring(2);
        else if (p.StartsWith("i=")) iterations = int.Parse(p.Substring(2));
    }

    if (serverNonce == null || saltB64 == null || iterations == 0)
        throw new Exception("Invalid server-first-message: " + serverFirst);

    // clientFinalWithoutProof = "c=biws,r=<serverNonce>"
    string clientFinalWithoutProof = $"c=biws,r={serverNonce}";

    authMessage = clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof;

    byte[] salt = Convert.FromBase64String(saltB64);
    // saltedPassword = Hi(password, salt, iterations) using PBKDF2-HMAC-SHA256
    using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
    return pbkdf2.GetBytes(32); // 32 bytes for SHA-256
}

static void SendSaslResponse(NetworkStream stream, string authMessage, byte[] saltedPassword)
{
    // compute clientProof
    byte[] clientKey = HmacSha256(saltedPassword, Encoding.UTF8.GetBytes("Client Key"));
    byte[] storedKey = Sha256(clientKey);
    byte[] clientSignature = HmacSha256(storedKey, Encoding.UTF8.GetBytes(authMessage));
    byte[] clientProof = Xor(clientKey, clientSignature);
    string clientProofB64 = Convert.ToBase64String(clientProof);

    // clientFinalMessage = clientFinalWithoutProof + ",p=<clientProofB64>"
    // We need the clientFinalWithoutProof; it is "c=biws,r=<serverNonce>" — but authMessage contains it as last part;
    // extract the final part from authMessage: authMessage = clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
    string clientFinalWithoutProof = authMessage.Substring(authMessage.LastIndexOf(',') + 1); // last segment
    string clientFinalMessage = clientFinalWithoutProof + ",p=" + clientProofB64;
    byte[] finalBytes = Encoding.UTF8.GetBytes(clientFinalMessage);

    using var ms = new MemoryStream();
    using var w = new BinaryWriter(ms);
    w.Write((byte)'p'); // SASLResponse (client continues)
                        // total length = 4 + finalBytes.Length
    WriteInt32BE(w, 4 + finalBytes.Length);
    w.Write(finalBytes);

    var bytes = ms.ToArray();
    stream.Write(bytes, 0, bytes.Length);
}

static void ValidateServerFinal(string serverFinal, byte[] saltedPassword, string authMessage)
{
    // serverFinal typically: "v=<base64 server signature>"
    if (string.IsNullOrEmpty(serverFinal)) return; // nothing to validate

    // If serverFinal contains "e=" (error), throw
    if (serverFinal.StartsWith("e="))
        throw new Exception("SCRAM error from server: " + serverFinal);

    string vPart = null;
    var parts = serverFinal.Split(',');
    foreach (var p in parts)
    {
        if (p.StartsWith("v=")) vPart = p.Substring(2);
    }
    if (vPart == null)
    {
        // No server signature provided — can't validate, but continue.
        Console.WriteLine("No server signature provided to validate.");
        return;
    }

    // serverKey = HMAC(saltedPassword, "Server Key")
    byte[] serverKey = HmacSha256(saltedPassword, Encoding.UTF8.GetBytes("Server Key"));
    byte[] serverSignature = HmacSha256(serverKey, Encoding.UTF8.GetBytes(authMessage));
    string expected = Convert.ToBase64String(serverSignature);
    if (!CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(vPart), serverSignature))
        throw new Exception($"SCRAM server signature mismatch. expected={expected} got={vPart}");
    Console.WriteLine("Server SCRAM signature validated.");
}

static string SendSCRAMInitial(NetworkStream stream, string username, string password)
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
    using var writer = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);
    writer.Write((byte)'p'); // SASLInitialResponse
    int totalLen = 4 + mechanismBytes.Length + 4 + clientFirstBytes.Length;
    WriteInt32BE(writer, totalLen);
    writer.Write(mechanismBytes); // mechanism
    WriteInt32BE(writer, clientFirstBytes.Length);
    writer.Write(clientFirstBytes);
    stream.Write(ms.ToArray(), 0, (int)ms.Length);

    // Read server-first-message
    //     char type = (char)stream.ReadByte();
    //     int length = ReadInt32BE(stream);
    //     byte[] payload = new byte[length];
    //     stream.Read(payload, 0, length);
    //     string serverFirst = Encoding.UTF8.GetString(payload);

    //     // Parse server nonce, salt, iterations
    //     var parts = serverFirst.Split(',');
    //     string serverNonce = parts[0].Substring(2);
    //     string salt = parts[1].Substring(2);
    //     int iterations = int.Parse(parts[2].Substring(2));

    //     // Client-final-message
    //     string channelBinding = "c=biws";
    //     string nonceFinal = $"r={serverNonce}";
    //     string authMessage = clientFirstMessageBare + "," + serverFirst + "," + channelBinding + "," + nonceFinal;

    //     byte[] saltedPassword = PBKDF2SHA256(password, Convert.FromBase64String(salt), iterations);
    //     byte[] clientKey = HMACSHA256(saltedPassword, "Client Key");
    //     byte[] storedKey = SHA256Hash(clientKey);
    //     byte[] clientSignature = HMACSHA256(storedKey, authMessage);
    //     byte[] clientProofBytes = XOR(clientKey, clientSignature);
    //     string clientProof = Convert.ToBase64String(clientProofBytes);

    //     string clientFinalMessage = $"{channelBinding},{nonceFinal},p={clientProof}";

    //     // Send client-final-message
    //     byte[] finalBytes = Encoding.UTF8.GetBytes(clientFinalMessage);
    //     using var ms2 = new MemoryStream();
    //     using var writer2 = new BinaryWriter(ms2);
    //     writer2.Write((byte)'p');
    //     WriteInt32BE(writer2, finalBytes.Length + 4 + 1);
    //     writer2.Write(finalBytes);
    //     stream.Write(ms2.ToArray(), 0, (int)ms2.Length);

    //     // Server-final-message
    //     type = (char)stream.ReadByte();
    //     length = ReadInt32BE(stream) - 4;
    //     SkipBytes(stream, length);

    //     Console.WriteLine("✅ SCRAM-SHA-256 authentication complete.");
    return nonce;
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


static short ReadInt16BE(Stream stream)
{
    Span<byte> buf = stackalloc byte[2];
    stream.Read(buf);
    return BinaryPrimitives.ReadInt16BigEndian(buf);
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

static (char type, byte[] payload) ReadMessage(NetworkStream stream)
{
    int t = stream.ReadByte();
    if (t == -1) throw new IOException("Connection closed by remote.");
    char type = (char)t;
    int len = ReadInt32BE(stream);
    if (len < 4) throw new Exception("Invalid message length: " + len);
    int payloadLen = len - 4;
    var payload = new byte[payloadLen];
    ReadExact(stream, payload, 0, payloadLen);
    return (type, payload);
}

static void ReadExact(Stream s, byte[] buffer, int offset, int count)
{
    int read = 0;
    while (read < count)
    {
        int n = s.Read(buffer, offset + read, count - read);
        if (n <= 0) throw new IOException("Unexpected EOF while reading.");
        read += n;
    }
}

static int ReadInt32BE(Stream s)
{
    Span<byte> buf = stackalloc byte[4];
    ReadExactSpan(s, buf);
    return BinaryPrimitives.ReadInt32BigEndian(buf);
}

// small overload to read into Span via stream
static void ReadExactSpan(Stream s, Span<byte> span)
{
    int offset = 0;
    while (offset < span.Length)
    {
        int n = s.Read(span.Slice(offset).ToArray(), 0, span.Length - offset);
        if (n <= 0) throw new IOException("Unexpected EOF while reading span.");
        offset += n;
    }
}

static int ReadInt32FromBuffer(byte[] buf, int offset)
    => BinaryPrimitives.ReadInt32BigEndian(new ReadOnlySpan<byte>(buf, offset, 4));

static short ReadInt16FromBuffer(byte[] buf, int offset)
    => BinaryPrimitives.ReadInt16BigEndian(new ReadOnlySpan<byte>(buf, offset, 2));

static void WriteInt32BE(BinaryWriter w, int value)
{
    Span<byte> span = stackalloc byte[4];
    BinaryPrimitives.WriteInt32BigEndian(span, value);
    w.Write(span.ToArray());
}

static byte[] SubArray(byte[] data, int index, int count)
{
    if (count <= 0) return Array.Empty<byte>();
    var result = new byte[count];
    Array.Copy(data, index, result, 0, count);
    return result;
}

static byte[] HmacSha256(byte[] key, byte[] data)
{
    using var h = new HMACSHA256(key);
    return h.ComputeHash(data);
}

static byte[] Sha256(byte[] data)
{
    using var s = SHA256.Create();
    return s.ComputeHash(data);
}

static byte[] Xor(byte[] a, byte[] b)
{
    var r = new byte[a.Length];
    for (int i = 0; i < a.Length; i++) r[i] = (byte)(a[i] ^ b[i]);
    return r;
}

// convenience: read into span using stream (safer than earlier attempts)
// static void ReadExact(Stream s, byte[] buffer)
// {
//     ReadExact(s, buffer, 0, buffer.Length);
// }
