// .NET 6+ recommended
using System;
using System.Buffers.Binary;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class RawPostgresScramClients
{
    static void Main()
    {
        string host = "127.0.0.1";
        int port = 5432;
        string user = "postgres";
        string password = "your_password"; // <- change
        string database = "postgres";

        using var client = new TcpClient();
        client.Connect(host, port);
        using var stream = client.GetStream();

        Console.WriteLine("Connected to PostgreSQL.");
        SendStartupMessage(stream, user, database);

        WaitForAuthenticationSCRAM(stream, user, password);

        SendQuery(stream, "SELECT 1;");
        ReadResponse(stream);

        SendTerminate(stream);
    }

    // ------------------- High level helpers -------------------

    static void SendStartupMessage(NetworkStream stream, string user, string database)
    {
        using var payload = new MemoryStream();
        using (var w = new BinaryWriter(payload, Encoding.UTF8, leaveOpen: true))
        {
            // Protocol 3.0
            WriteInt32BE(w, 196608);

            WriteCString(w, "user");
            WriteCString(w, user);
            WriteCString(w, "database");
            WriteCString(w, database);

            w.Write((byte)0); // terminator
        }

        var payloadBytes = payload.ToArray();
        int length = payloadBytes.Length + 4; // length includes itself

        using var ms = new MemoryStream();
        using var w2 = new BinaryWriter(ms);
        WriteInt32BE(w2, length);
        w2.Write(payloadBytes);

        stream.Write(ms.ToArray(), 0, (int)ms.Length);
        Console.WriteLine("Sent StartupMessage.");
    }

    static void WaitForAuthenticationSCRAM(NetworkStream stream, string username, string password)
    {
        // We'll keep the client-first-bare and nonce until needed
        string clientFirstBare = null;
        string clientNonce = null;
        byte[] saltedPassword = null;
        string authMessage = null;
        var authenticated = false;

        while (true)
        {
            var (type, payload) = ReadMessage(stream);

            if (type == 'R') // Authentication messages
            {
                if (payload.Length < 4) throw new Exception("Authentication message too short.");
                int authType = ReadInt32FromBuffer(payload, 0);
                var rest = SubArray(payload, 4, Math.Max(0, payload.Length - 4));

                switch (authType)
                {
                    case 10: // AuthenticationSASL - server lists mechanisms
                        {
                            string mechs = Encoding.UTF8.GetString(rest).TrimEnd('\0');
                            if (!mechs.Contains("SCRAM-SHA-256"))
                                throw new Exception("Server does not offer SCRAM-SHA-256.");

                            // Send SASLInitialResponse (mechanism + int32 initial-response-length + initial-response)
                            clientNonce = SendSaslInitial(stream, username, out clientFirstBare);
                            Console.WriteLine("Sent SASLInitialResponse.");
                            break;
                        }

                    case 11: // AuthenticationSASLContinue (server-first-message)
                        {
                            string serverFirst = Encoding.UTF8.GetString(rest);
                            // serverFirst should be like: r=<nonce>,s=<base64salt>,i=<iterations>
                            // Compute salted password and send SASLResponse (client-final-message)
                            saltedPassword = ComputeSaltedPassword(password, serverFirst, out authMessage, clientFirstBare, clientNonce);
                            SendSaslResponse(stream, authMessage, saltedPassword);
                            Console.WriteLine("Sent SASLResponse (client-final).");
                            break;
                        }

                    case 12: // AuthenticationSASLFinal (server-final-message)
                        {
                            string serverFinal = Encoding.UTF8.GetString(rest);
                            // Usually contains v=<serverSignature> or an error.
                            ValidateServerFinal(serverFinal, saltedPassword, authMessage);
                            Console.WriteLine("Received server-final-message.");
                            break;
                        }

                    case 0: // AuthenticationOk
                        {
                            Console.WriteLine("AuthenticationOk received.");
                            authenticated = true;
                            break;
                        }

                    default:
                        throw new Exception($"Unsupported auth type: {authType}");
                }
            }
            else if (type == 'S' || type == 'K')
            {
                // ParameterStatus or BackendKeyData: ignore for now
            }
            else if (type == 'E')
            {
                string err = Encoding.UTF8.GetString(payload);
                throw new Exception("Error from server: " + err);
            }
            else if (type == 'Z') // ReadyForQuery
            {
                // payload could contain a status byte; we are ready once we have AuthenticationOk
                Console.WriteLine("ReadyForQuery received.");
                if (!authenticated)
                    Console.WriteLine("Warning: ReadyForQuery received before AuthenticationOk.");
                return;
            }
            else
            {
                // ignore other messages
            }
        }
    }

    // ------------------- SCRAM message builders / parsers -------------------

    // Sends SASLInitialResponse. Returns client nonce and outputs clientFirstBare.
    static string SendSaslInitial(NetworkStream stream, string username, out string clientFirstBare)
    {
        // NOTE: we are not doing SASLprep on username here (simplification).
        byte[] nonceBytes = new byte[18];
        RandomNumberGenerator.Fill(nonceBytes);
        string clientNonce = Convert.ToBase64String(nonceBytes);

        clientFirstBare = $"n={username},r={clientNonce}";          // e.g. "n=postgres,r=..."
        string clientFirstMessage = "n,," + clientFirstBare;       // "n,,n=...,r=..."

        byte[] clientFirstBytes = Encoding.UTF8.GetBytes(clientFirstMessage);
        byte[] mech = Encoding.UTF8.GetBytes("SCRAM-SHA-256\0");   // null-terminated mechanism name

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        w.Write((byte)'p'); // SASLInitialResponse message type

        // total length = 4 + mechanism (including null) + 4 (initial-response length) + initial-response bytes
        int totalLen = 4 + mech.Length + 4 + clientFirstBytes.Length;
        WriteInt32BE(w, totalLen);

        w.Write(mech); // mechanism name + null
        WriteInt32BE(w, clientFirstBytes.Length); // initial response length
        w.Write(clientFirstBytes); // initial response

        var bytes = ms.ToArray();
        stream.Write(bytes, 0, bytes.Length);
        return clientNonce;
    }

    // Given server-first message string, compute saltedPassword and authMessage (for later validation).
    // Also returns saltedPassword (used later to verify server signature).
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

    // ------------------- Query / response / terminate -------------------

    static void SendQuery(NetworkStream stream, string query)
    {
        byte[] queryBytes = Encoding.UTF8.GetBytes(query + "\0");
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write((byte)'Q');
        WriteInt32BE(w, 4 + queryBytes.Length); // length includes itself
        w.Write(queryBytes);

        var bytes = ms.ToArray();
        stream.Write(bytes, 0, bytes.Length);
        Console.WriteLine("Sent Query: " + query);
    }

    static void ReadResponse(NetworkStream stream)
    {
        while (true)
        {
            var (type, payload) = ReadMessage(stream);
            if (type == 'T') // RowDescription
            {
                short fieldCount = ReadInt16FromBuffer(payload, 0);
                Console.WriteLine($"RowDescription: {fieldCount} fields");
                // skip the rest (we're keeping sample small)
            }
            else if (type == 'D') // DataRow
            {
                short cols = ReadInt16FromBuffer(payload, 0);
                int offset = 2;
                Console.Write("Row: ");
                for (int i = 0; i < cols; i++)
                {
                    int colLen = ReadInt32FromBuffer(payload, offset);
                    offset += 4;
                    if (colLen == -1)
                    {
                        Console.Write("NULL");
                    }
                    else
                    {
                        string val = Encoding.UTF8.GetString(payload, offset, colLen);
                        Console.Write(val);
                        offset += colLen;
                    }
                    if (i < cols - 1) Console.Write(", ");
                }
                Console.WriteLine();
            }
            else if (type == 'C') // CommandComplete
            {
                string s = Encoding.UTF8.GetString(payload, 0, payload.Length - 1); // trailing null usually
                Console.WriteLine("CommandComplete: " + s);
            }
            else if (type == 'Z') // ReadyForQuery
            {
                Console.WriteLine("ReadyForQuery.");
                return;
            }
            else if (type == 'E') // ErrorResponse
            {
                Console.WriteLine("ErrorResponse: " + Encoding.UTF8.GetString(payload));
                return;
            }
            else
            {
                // other messages - ignore for now
            }
        }
    }

    static void SendTerminate(NetworkStream stream)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write((byte)'X');
        WriteInt32BE(w, 4);
        var b = ms.ToArray();
        stream.Write(b, 0, b.Length);
    }

    // ------------------- Low-level framing & helpers -------------------

    // Reads exactly one backend/frontend message: type byte + int32(len) + payload bytes
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
        ReadExact(s, buf);
        return BinaryPrimitives.ReadInt32BigEndian(buf);
    }

    // small overload to read into Span via stream
    static void ReadExact(Stream s, Span<byte> span)
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

    static void WriteCString(BinaryWriter w, string s)
    {
        w.Write(Encoding.UTF8.GetBytes(s));
        w.Write((byte)0);
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
    static void ReadExact(Stream s, byte[] buffer)
    {
        ReadExact(s, buffer, 0, buffer.Length);
    }
}
