using PgClient.Response;
using PgClient.Types;

namespace PgClient.Query;

/// A parameter bound to an extended-query message. Choose an explicit
/// <see cref="TypeOid"/> to force server-side coercion; leave it at 0
/// (default) to let the server pick a type from context.
public sealed class PgParameter
{
    /// Optional logical name (not part of the wire protocol; useful for callers).
    public string Name { get; set; } = string.Empty;

    /// Postgres type OID. 0 means "unspecified".
    public uint TypeOid { get; set; }

    public object? Value { get; set; }

    /// Wire format used for both sending and reading the value.
    public PgFormatCode FormatCode { get; set; } = PgFormatCode.Text;

    public PgParameter() { }

    public PgParameter(object? value, uint typeOid = 0, PgFormatCode format = PgFormatCode.Text)
    {
        Value = value;
        TypeOid = typeOid;
        FormatCode = format;
    }

    // --- Convenience factories ---------------------------------------------

    public static PgParameter Text(string? value) => new(value, PgOid.Text);
    public static PgParameter Int2(short value) => new(value, PgOid.Int2);
    public static PgParameter Int4(int value) => new(value, PgOid.Int4);
    public static PgParameter Int8(long value) => new(value, PgOid.Int8);
    public static PgParameter Float4(float value) => new(value, PgOid.Float4);
    public static PgParameter Float8(double value) => new(value, PgOid.Float8);
    public static PgParameter Bool(bool value) => new(value, PgOid.Bool);
    public static PgParameter Numeric(decimal value) => new(value, PgOid.Numeric);
    public static PgParameter Uuid(Guid value) => new(value, PgOid.Uuid);
    public static PgParameter Bytea(byte[] value) => new(value, PgOid.Bytea);
    public static PgParameter Timestamp(DateTime v) => new(v, PgOid.Timestamp);
    public static PgParameter TimestampTz(DateTime v) => new(v, PgOid.TimestampTz);
    public static PgParameter Date(DateOnly value) => new(value, PgOid.Date);
    public static PgParameter Json(string value) => new(value, PgOid.Json);
    public static PgParameter Jsonb(string value) => new(value, PgOid.Jsonb);

    public static PgParameter Null(uint typeOid = 0) => new(null, typeOid);

    /// Encodes the parameter's value to a byte payload using the supplied registry.
    /// Returns null when the parameter carries a SQL NULL.
    public byte[]? Encode(PgTypeRegistry registry)
    {
        if (Value is null || Value is DBNull) return null;

        // Choose OID: explicit > CLR-type lookup.
        uint oid = TypeOid;
        PgTypeHandler? handler = oid != 0 ? registry.Get(oid) : null;
        if (handler is null)
        {
            handler = registry.GetForClrType(Value.GetType());
            if (handler is not null && TypeOid == 0)
                TypeOid = handler.TypeOid;
        }

        if (handler is null)
        {
            // Fallback: stringify.
            var s = Convert.ToString(Value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
            return System.Text.Encoding.UTF8.GetBytes(s);
        }

        return handler.Encode(Value, FormatCode);
    }
}
