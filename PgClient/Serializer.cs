using PgClient.Protocol;

namespace PgClient;

public class Serializer
{
    private StatusCodes statusCodes;
    private BufferWriter Writer;


    public byte[] StartUpBytes(Dictionary<string, string> options)
    {
        using var Writer = new BufferWriter();
        Writer.WriteInt16(Convert.ToInt16(PostgresProtocol.ProtocolVersion)); ///protocol version 3
        Writer.WriteInt16(0); ///empty byte

        foreach (var option in options)
        {
            Writer.WriteCString(option.Key);
            Writer.WriteCString(option.Value);
        }

        Writer.WriteCString("client_encoding");
        Writer.WriteCString("UTF8");

        using var finalWriter = new BufferWriter();
        var contentBytes = Writer.WrittenBytes;
        int totalLength = contentBytes.Length + 4;

        finalWriter.WriteInt32(totalLength);
        finalWriter.WriteBytes(contentBytes);
        return finalWriter.WrittenBytes;
    }

    public void SendSASLIntial(string mechanism, string initialResponse )
    {
        using var Writer = new BufferWriter();
    }
}