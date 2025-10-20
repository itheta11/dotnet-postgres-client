using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using PgClient.Protocol;
namespace PgClient.Authentication;

public class AuthenticationHandler
{
    private readonly ConnectionParameters _connectionParams;
    private string _mechanisms = "SCRAM-SHA-256";

    private string _clientFirstMessagebare = "";
    private string _clientNonce = "";
    private string _serverNonce = "";
    private byte[] _saltedPassword;
    private string _authMessage = "";
    public AuthenticationHandler(ConnectionParameters connectionParameters)
    {
        _connectionParams = connectionParameters;
    }

    /// <summary>
    /// Authenctication handler
    /// </summary>
    /// <param name="payload">payload excluding the intial code. i.e total length + rest of the bytes</param>
    /// <param name="stream">TCP network stream of the server</param>
    /// <exception cref="Exception"></exception>
    public void Handler(byte[] payload, NetworkStream stream)
    {
        if (payload.Length < 4) throw new Exception("Authentication message too short.");
        using BufferReader reader = new BufferReader();
        reader.SetBuffer(payload);
        int authType = reader.ReadInt32();

        switch ((PostgresProtocol.AuthenticationCode)authType)
        {
            case PostgresProtocol.AuthenticationCode.Ok:
                Console.WriteLine("Authentication successful");
                break;
            case PostgresProtocol.AuthenticationCode.SASL:
                ///Client → SASLInitialResponse
                string mechanism = reader.ReadCString().TrimEnd('\0');
                if (!mechanism.Contains(_mechanisms))
                {
                    throw new Exception("SCRAM-SHA-256 not supported by server.");
                }
                SendSASLIntial(stream, mechanism, _connectionParams);
                break;
            case PostgresProtocol.AuthenticationCode.SASLContinue:
                string serverFirstMessage = Encoding.UTF8.GetString(payload)
                        .Replace("\0", string.Empty)
                        .Replace("\v", string.Empty);
                AuthSASLContinue(stream, serverFirstMessage);
                break;
            case PostgresProtocol.AuthenticationCode.SASLFinal:
                string serverFinal = Encoding.UTF8.GetString(payload)
                        .Replace("\0", string.Empty)
                        .Replace("\v", string.Empty);
                ValidateServerFinal(serverFinal, _saltedPassword, _authMessage);
                break;

            default:
                break;
        }


    }
    /// <summary>
    /// Client → SASLInitialResponse
    /// Intial sasl response from client to server
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="mechanism"></param>
    /// <param name="connectionParams"></param>
    public void SendSASLIntial(NetworkStream stream, string mechanism, ConnectionParameters connectionParams)
    {
        string nonce = CreateClientNonce();

        // client-first-message
        string clientFirstMessageBare = $"n=*,r={nonce}";
        //string clientFirstMessageBare = $"n=*,r={nonce}";
        _clientFirstMessagebare = clientFirstMessageBare;
        string clientFirstMessage = $"n,,{clientFirstMessageBare}";
        /// Example n,,n=postgres,r=fyko+d2lbbFgONRv9qkxdawL

        byte[] clientFirstMessageBytes = Encoding.UTF8.GetBytes(clientFirstMessage);
        //byte[] mechanismBytes = Encoding.UTF8.GetBytes($"{mechanism}\0");

        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);
        writer.Write((byte)PostgresProtocol.FrontendMessageCode.PasswordMessage);
        writer.Write(new byte[4]); /// placeholder for length
        Helper.WriteCString(writer, mechanism);
        writer.Write(Helper.ToBigEndian(clientFirstMessageBytes.Length));
        writer.Write(clientFirstMessageBytes);

        int totalLength = (int)ms.Length - 1;
        ms.Position = 1;
        writer.Write(Helper.ToBigEndian(totalLength));
        stream.Write(ms.ToArray(), 0, ms.ToArray().Length);
    }

    /// <summary>
    /// Server → AuthenticationSASLContinue
    /// Code: 'R' + int32 length + int32 code=11 (AuthenticationSASLContinue)
    /// Structure
    ///     Byte1('R')
    ///     Int32(Length)
    ///     Int32(11)
    ///     ByteN(server_first_message)
    /// Message format
    ///     r=client_nonce + server_nonce,s=salt_b64,i=iterations
    /// </summary>
    /// <param name="stream"></param>
    /// <param name="firstServerMessage"></param>
    public void AuthSASLContinue(NetworkStream stream, string firstServerMessage)
    {
        var (authMessage, saltedPasswordBytes) = ComputeSaltPassword(firstServerMessage);
        /// Client → SASLResponse
        /// Code: 'p' (PasswordMessage)
        /// Structure
        ///     Byte1('p')
        ///     Int32(length)
        ///     ByteN(client_final_message)
        /// Message - c=biws,r=combined_nonce,p=client_proof_b64
        /// 
        /// Steps for calulating p:
        /// SaltedPassword = PBKDF2-HMAC-SHA-256(password, salt, i)
        /// ClientKey = HMAC(SaltedPassword, "Client Key")
        /// StoredKey = SHA256(ClientKey)
        /// AuthMessage = concat of: 
        ///     client-first-message-bare + "," +
        ///     server-first-message + "," +
        ///     client-final-message-without-proof
        /// ClientSignature = HMAC(StoredKey, AuthMessage)
        /// ClientProof = XOR(ClientKey, ClientSignature)
        /// Base64(ClientProof) = sent as p=...

        int len = saltedPasswordBytes.Length;
        _saltedPassword = new byte[len];
        Buffer.BlockCopy(saltedPasswordBytes, 0, _saltedPassword, 0, len);
        _authMessage = authMessage;
        SendServerSaslResponse(stream, authMessage, saltedPasswordBytes);

    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="firstServerMessage"></param>
    /// <returns>(authMessage and saltedPassword)</returns>
    /// <exception cref="Exception"></exception>
    private (string authMessage, byte[] saltedPasswordBytes) ComputeSaltPassword(string firstServerMessage)
    {
        // parse serverFirst: "r=<nonce>,s=<salt>,i=<iterations>"
        string serverNonce = null;
        string saltB64 = null;
        int iterations = 0;
        var parts = firstServerMessage.Split(',');
        foreach (var p in parts)
        {
            if (p.Contains("r="))
            {
                int index = p.IndexOf("r=");
                serverNonce = p.Substring(index + 2);
                //serverNonce = "/J6vYp8OMZMcH+aAe8c0PaEkM+LJh9c16Tm8cfhoMROnId1s";
                _serverNonce = serverNonce;
            }
            else if (p.StartsWith("s="))
            {
                int index = p.IndexOf("s=");
                saltB64 = p.Substring(index + 2);
                //saltB64 = "hmg0S4alnHPaCBMJDTR5mA==";
            }
            else if (p.StartsWith("i="))
            {
                int index = p.IndexOf("i=");
                iterations = int.Parse(p.Substring(index + 2));
                //iterations = 4096;
            }
        }

        if (serverNonce == null || saltB64 == null || iterations == 0)
            throw new Exception("Invalid server-first-message: " + firstServerMessage);

        // clientFinalWithoutProof = "c=biws,r=<serverNonce>"
        string clientFinalWithoutProof = $"c=biws,r={serverNonce}";

        string authMessage = $"{_clientFirstMessagebare},{firstServerMessage},{clientFinalWithoutProof}";
        //string authMessage = "n=*,r=/J6vYp8OMZMcH+aAe8c0PaEk,r=/J6vYp8OMZMcH+aAe8c0PaEkM+LJh9c16Tm8cfhoMROnId1s,s=hmg0S4alnHPaCBMJDTR5mA==,i=4096,c=biws,r=/J6vYp8OMZMcH+aAe8c0PaEkM+LJh9c16Tm8cfhoMROnId1s";
        Console.WriteLine($"auth message - {authMessage}");
        byte[] salt = Convert.FromBase64String(saltB64);
        byte[] saltedPasswordBytes = PBKDF2SHA256(_connectionParams.Password, salt, iterations);
        //byte[] saltedPasswordBytes = Hi(Encoding.UTF8.GetBytes(SaslPrep(_connectionParams.Password)), salt, iterations);

        return (authMessage, saltedPasswordBytes);
    }

    /// <summary>
    /// 
    /// Steps for calulating p:
    /// SaltedPassword = PBKDF2-HMAC-SHA-256(password, salt, i)
    /// ClientKey = HMAC(SaltedPassword, "Client Key")
    /// StoredKey = SHA256(ClientKey)
    /// AuthMessage = concat of: 
    ///     client-first-message-bare + "," +
    ///     server-first-message + "," +
    ///     client-final-message-without-proof
    /// ClientSignature = HMAC(StoredKey, AuthMessage)
    /// ClientProof = XOR(ClientKey, ClientSignature)
    /// </summary>
    /// <returns></returns>
    private void SendServerSaslResponse(NetworkStream stream, string authMessage, byte[] saltedPasswordBytes)
    {
        byte[] clientKey = HmacSha256(saltedPasswordBytes, "Client Key");
        byte[] storedKey = ShaHash256(clientKey);
        byte[] clientSignature = HmacSha256(storedKey, authMessage);
        byte[] clientProof = Xor(clientKey, clientSignature);
        string clientProofB64 = Convert.ToBase64String(clientProof);

        // clientFinalMessage = clientFinalWithoutProof + ",p=<clientProofB64>"
        // clientFinalWithoutProof; it is "c=biws,r=<serverNonce>" — but authMessage contains it as last part;
        // extract the final part from authMessage: authMessage = clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
        string clientFinalWithoutProof = authMessage.Substring(authMessage.LastIndexOf(',') + 1); // last segment
        string clientFinalMessage = $"c=biws,r={_serverNonce},p={clientProofB64}";
        ///c=biws,r=/J6vYp8OMZMcH+aAe8c0PaEkM+LJh9c16Tm8cfhoMROnId1s,p=+9JcUS6n9iVWjPrqI6bpXHtdptjXlRGg/Nv1RgJhC4k=
        Console.WriteLine($"Client final message - {clientFinalMessage}");
        byte[] finalBytes = Encoding.UTF8.GetBytes(clientFinalMessage);
        int totalLength = finalBytes.Length + 4;
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        writer.Write((byte)PostgresProtocol.FrontendMessageCode.PasswordMessage);

        long lengthPosition = ms.Position;
        writer.Write(0); //placeholder for length
        writer.Write(finalBytes);

        long endPosition = ms.Position;
        int length = (int)(endPosition - 1);
        ms.Position = lengthPosition;
        writer.Write(Helper.ToBigEndian(length));

        ms.Position = 0;
        stream.Write(ms.ToArray(), 0, ms.ToArray().Length);
    }



    /// <summary>
    /// have to revisit
    /// </summary>
    /// <param name="serverFinal"></param>
    /// <param name="saltedPassword"></param>
    /// <param name="authMessage"></param>
    /// <exception cref="Exception"></exception>
    private void ValidateServerFinal(string serverFinal, byte[] saltedPassword, string authMessage)
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
        byte[] serverKey = HmacSha256(saltedPassword, "Server Key");
        byte[] serverSignature = HmacSha256(serverKey, authMessage);
        string expected = Convert.ToBase64String(serverSignature);
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(vPart), serverSignature))
            throw new Exception($"SCRAM server signature mismatch. expected={expected} got={vPart}");
    }

    private string CreateClientNonce()
    {
        byte[] nonceBytes = new byte[18]; // 18 bytes = 24 base64 chars
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(nonceBytes);
        }
        string nonce = Convert.ToBase64String(nonceBytes);
        _clientNonce = nonce;
        return nonce;
    }

    private byte[] PBKDF2SHA256(string password, byte[] salt, int iterations)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }

    private byte[] HmacSha256(byte[] key, string message)
    {
        using var h = new HMACSHA256(key);
        return h.ComputeHash(Encoding.UTF8.GetBytes(message));
    }

    private byte[] ShaHash256(byte[] data)
    {
        using var s = SHA256.Create();
        return s.ComputeHash(data);
    }

    private byte[] Xor(byte[] a, byte[] b)
    {
        var r = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
        {
            r[i] = (byte)(a[i] ^ b[i]);
        }
        return r;
    }

    private byte[] Hi(byte[] password, byte[] salt, int iterations)
    {
        using (var hmac = new HMACSHA256(password))
        {
            // PBKDF2 with HMAC-SHA-256
            byte[] saltWithIndex = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, saltWithIndex, 0, salt.Length);
            saltWithIndex[salt.Length + 3] = 1; // INT(1) in big-endian

            byte[] u = hmac.ComputeHash(saltWithIndex);
            byte[] result = (byte[])u.Clone();

            for (int i = 1; i < iterations; i++)
            {
                u = hmac.ComputeHash(u);
                XorInPlace(result, u);
            }

            return result;
        }
    }

    private void XorInPlace(byte[] target, byte[] source)
    {
        for (int i = 0; i < target.Length; i++)
        {
            target[i] ^= source[i];
        }
    }

    private string SaslPrep(string input)
    {
        // Simplified SASLprep - for production, use proper normalization
        // This handles basic cases but may need RFC 4013 compliance
        return input.Normalize(NormalizationForm.FormKC);
    }
}