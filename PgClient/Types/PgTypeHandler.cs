using PgClient.Response;

namespace PgClient.Types;

/// Encodes/decodes a single Postgres data type between the wire format and CLR values.
///
/// v1 implements text-format for all handlers and binary-format for the common
/// fixed-width primitives (bool, int2/4/8, float4/8, uuid, bytea). Callers that
/// need binary format for other types can register their own handler.
public abstract class PgTypeHandler
{
    public abstract uint TypeOid { get; }
    public abstract Type ClrType { get; }
    public virtual bool SupportsBinary => false;

    public abstract object ReadText(ReadOnlySpan<byte> bytes);
    public virtual object ReadBinary(ReadOnlySpan<byte> bytes)
        => throw new NotSupportedException($"Binary read is not implemented for OID {TypeOid}.");

    public abstract byte[] EncodeText(object value);
    public virtual byte[] EncodeBinary(object value)
        => throw new NotSupportedException($"Binary write is not implemented for OID {TypeOid}.");

    public object Read(ReadOnlySpan<byte> bytes, PgFormatCode format)
        => format == PgFormatCode.Binary ? ReadBinary(bytes) : ReadText(bytes);

    public byte[] Encode(object value, PgFormatCode format)
        => format == PgFormatCode.Binary ? EncodeBinary(value) : EncodeText(value);
}
