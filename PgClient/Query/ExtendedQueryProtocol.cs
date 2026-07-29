using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using PgClient.BufferUtils;
using PgClient.Protocol;
using PgClient.Response;
using PgClient.Types;
using PgClient.Utilities;

namespace PgClient.Query;

/// Writes the extended-query protocol frames (Parse / Bind / Describe / Execute / Sync / Close).
/// All writes are big-endian; frontend framing is
///   byte code | Int32 length (of length + body) | body.
public static class ExtendedQueryProtocol
{
    /// Sends Parse + Bind + Describe(Portal) + Execute + Sync in a single flush.
    /// The reader returned by the caller (via PgDataReader) will consume:
    ///   ParseComplete, BindComplete, RowDescription/NoData, DataRow*, CommandComplete, ReadyForQuery.
    public static void SendParseBindExecute(
        Stream stream,
        string statementName,
        string portalName,
        string sql,
        IReadOnlyList<PgParameter> parameters,
        PgTypeRegistry registry,
        int maxRows = 0)
    {
        // Serialise each parameter first — we need the byte payloads for length prefixes.
        byte[]?[] encoded = new byte[]?[parameters.Count];
        for (int i = 0; i < parameters.Count; i++)
            encoded[i] = parameters[i].Encode(registry);

        WriteParse(stream, statementName, sql, parameters);
        WriteBind(stream, portalName, statementName, parameters, encoded);
        WriteDescribePortal(stream, portalName);
        WriteExecute(stream, portalName, maxRows);
        WriteSync(stream);
    }

    /// Parse: 'P' | Int32 len | CString stmt | CString query | Int16 nparams | Int32 oid * nparams
    public static void WriteParse(Stream stream, string statementName, string sql, IReadOnlyList<PgParameter> parameters)
    {
        int stmtLen = Encoding.UTF8.GetByteCount(statementName) + 1;
        int sqlLen = Encoding.UTF8.GetByteCount(sql) + 1;
        int paramCountBytes = 2 + parameters.Count * 4;
        int body = 4 + stmtLen + sqlLen + paramCountBytes;
        int total = 1 + body;

        byte[] buf = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            int pos = 0;
            buf[pos++] = (byte)PostgresProtocol.FrontendMessageCode.Parse;
            BinaryPrimitives.WriteInt32BigEndian(buf.AsSpan(pos, 4), body); pos += 4;
            pos += WriteCString(buf.AsSpan(pos), statementName);
            pos += WriteCString(buf.AsSpan(pos), sql);
            BinaryPrimitives.WriteInt16BigEndian(buf.AsSpan(pos, 2), (short)parameters.Count); pos += 2;
            for (int i = 0; i < parameters.Count; i++)
            {
                BinaryPrimitives.WriteInt32BigEndian(buf.AsSpan(pos, 4), (int)parameters[i].TypeOid);
                pos += 4;
            }
            stream.Write(buf, 0, total);
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    /// Bind: 'B' | Int32 len | CString portal | CString stmt
    ///        | Int16 formatCount | Int16 format*formatCount
    ///        | Int16 paramCount | (Int32 len | bytes)*paramCount
    ///        | Int16 resultFormatCount | Int16 resultFormat*resultFormatCount
    public static void WriteBind(
        Stream stream, string portalName, string statementName,
        IReadOnlyList<PgParameter> parameters, byte[]?[] encoded)
    {
        int portalLen = Encoding.UTF8.GetByteCount(portalName) + 1;
        int stmtLen = Encoding.UTF8.GetByteCount(statementName) + 1;

        int paramsSize = 2 /*count*/;
        for (int i = 0; i < encoded.Length; i++)
            paramsSize += 4 + (encoded[i]?.Length ?? 0);

        int body = 4 + portalLen + stmtLen
                   + 2 + parameters.Count * 2  // param formats (per-parameter)
                   + paramsSize
                   + 2 + 2;                     // result format count(=1) + Text
        int total = 1 + body;

        byte[] buf = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            int pos = 0;
            buf[pos++] = (byte)PostgresProtocol.FrontendMessageCode.Bind;
            BinaryPrimitives.WriteInt32BigEndian(buf.AsSpan(pos, 4), body); pos += 4;
            pos += WriteCString(buf.AsSpan(pos), portalName);
            pos += WriteCString(buf.AsSpan(pos), statementName);

            // Per-parameter format codes.
            BinaryPrimitives.WriteInt16BigEndian(buf.AsSpan(pos, 2), (short)parameters.Count); pos += 2;
            for (int i = 0; i < parameters.Count; i++)
            {
                BinaryPrimitives.WriteInt16BigEndian(buf.AsSpan(pos, 2), (short)parameters[i].FormatCode);
                pos += 2;
            }

            // Parameter values.
            BinaryPrimitives.WriteInt16BigEndian(buf.AsSpan(pos, 2), (short)encoded.Length); pos += 2;
            for (int i = 0; i < encoded.Length; i++)
            {
                byte[]? v = encoded[i];
                if (v is null)
                {
                    BinaryPrimitives.WriteInt32BigEndian(buf.AsSpan(pos, 4), -1); pos += 4;
                }
                else
                {
                    BinaryPrimitives.WriteInt32BigEndian(buf.AsSpan(pos, 4), v.Length); pos += 4;
                    v.CopyTo(buf.AsSpan(pos)); pos += v.Length;
                }
            }

            // Ask the server to send results in text format so PgDataReader (v1) can parse them.
            BinaryPrimitives.WriteInt16BigEndian(buf.AsSpan(pos, 2), 1); pos += 2;
            BinaryPrimitives.WriteInt16BigEndian(buf.AsSpan(pos, 2), (short)PgFormatCode.Text); pos += 2;

            stream.Write(buf, 0, total);
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    /// Describe: 'D' | Int32 len | byte('S'|'P') | CString name
    public static void WriteDescribeStatement(Stream stream, string name) => WriteDescribe(stream, (byte)'S', name);
    public static void WriteDescribePortal(Stream stream, string name) => WriteDescribe(stream, (byte)'P', name);

    private static void WriteDescribe(Stream stream, byte kind, string name)
    {
        int nameLen = Encoding.UTF8.GetByteCount(name) + 1;
        int body = 4 + 1 + nameLen;
        int total = 1 + body;

        byte[] buf = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            int pos = 0;
            buf[pos++] = (byte)PostgresProtocol.FrontendMessageCode.Describe;
            BinaryPrimitives.WriteInt32BigEndian(buf.AsSpan(pos, 4), body); pos += 4;
            buf[pos++] = kind;
            pos += WriteCString(buf.AsSpan(pos), name);
            stream.Write(buf, 0, total);
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    /// Execute: 'E' | Int32 len | CString portal | Int32 maxRows
    public static void WriteExecute(Stream stream, string portalName, int maxRows)
    {
        int portalLen = Encoding.UTF8.GetByteCount(portalName) + 1;
        int body = 4 + portalLen + 4;
        int total = 1 + body;

        byte[] buf = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            int pos = 0;
            buf[pos++] = (byte)PostgresProtocol.FrontendMessageCode.Execute;
            BinaryPrimitives.WriteInt32BigEndian(buf.AsSpan(pos, 4), body); pos += 4;
            pos += WriteCString(buf.AsSpan(pos), portalName);
            BinaryPrimitives.WriteInt32BigEndian(buf.AsSpan(pos, 4), maxRows);
            stream.Write(buf, 0, total);
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    /// Sync: 'S' | Int32 len (=4)
    public static void WriteSync(Stream stream)
    {
        Span<byte> b = stackalloc byte[5];
        b[0] = (byte)PostgresProtocol.FrontendMessageCode.Sync;
        BinaryPrimitives.WriteInt32BigEndian(b.Slice(1), 4);
        stream.Write(b);
    }

    /// Close: 'C' | Int32 len | byte('S'|'P') | CString name
    public static void WriteCloseStatement(Stream stream, string name) => WriteClose(stream, (byte)'S', name);
    public static void WriteClosePortal(Stream stream, string name) => WriteClose(stream, (byte)'P', name);

    private static void WriteClose(Stream stream, byte kind, string name)
    {
        int nameLen = Encoding.UTF8.GetByteCount(name) + 1;
        int body = 4 + 1 + nameLen;
        int total = 1 + body;
        byte[] buf = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            int pos = 0;
            buf[pos++] = (byte)PostgresProtocol.FrontendMessageCode.Close;
            BinaryPrimitives.WriteInt32BigEndian(buf.AsSpan(pos, 4), body); pos += 4;
            buf[pos++] = kind;
            pos += WriteCString(buf.AsSpan(pos), name);
            stream.Write(buf, 0, total);
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    private static int WriteCString(Span<byte> dest, string value)
    {
        int n = Encoding.UTF8.GetBytes(value, dest);
        dest[n] = 0;
        return n + 1;
    }
}
