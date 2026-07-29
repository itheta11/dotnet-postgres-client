using System.Text;
using PgClient.BufferUtils;
using PgClient.Protocol;
using PgClient.Response;
using PgClient.Utilities;

namespace PgClient.QueryController;

public sealed class PgQueryController
{
    /// Executes a simple-protocol Query and returns a streaming reader over the results.
    /// The reader must be disposed to drain the connection back to ReadyForQuery.
    public PgDataReader ExecuteReader(
        Stream stream,
        BufferStreamReader protocolReader,
        string query,
        Action<PostgresProtocol.TransactionStatus>? onReadyForQuery = null,
        Action<PgErrorInfo>? onNotice = null,
        Action<ReadOnlyMemory<byte>>? onParameterStatus = null)
    {
        SendQuery(stream, query);
        return new PgDataReader(stream, protocolReader, onReadyForQuery, onNotice, onParameterStatus);
    }

    /// Writes a simple-query message: Q | Int32 length | CString query
    public static void SendQuery(Stream stream, string query)
    {
        int queryByteCount = Encoding.UTF8.GetByteCount(query);
        int totalLen = 1 + 4 + queryByteCount + 1; // code + length + query + NUL
        int payloadLen = 4 + queryByteCount + 1;   // length prefix + query + NUL

        byte[] buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(totalLen);
        try
        {
            buffer[0] = (byte)PostgresProtocol.FrontendMessageCode.Query;
            Helper.WriteInt32BE(buffer.AsSpan(1, 4), payloadLen);
            int written = Encoding.UTF8.GetBytes(query, buffer.AsSpan(5, queryByteCount));
            buffer[5 + written] = 0;
            stream.Write(buffer, 0, totalLen);
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static void SendTerminate(Stream stream)
    {
        Span<byte> buf = stackalloc byte[5];
        buf[0] = (byte)PostgresProtocol.FrontendMessageCode.Terminate;
        Helper.WriteInt32BE(buf.Slice(1, 4), 4);
        stream.Write(buf);
    }
}
