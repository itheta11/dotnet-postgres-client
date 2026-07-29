namespace PgClient.Response;

/// Well-known Postgres built-in type OIDs (from src/include/catalog/pg_type.dat).
public static class PgOid
{
    public const uint Bool = 16;
    public const uint Bytea = 17;
    public const uint Char = 18;
    public const uint Name = 19;
    public const uint Int8 = 20;
    public const uint Int2 = 21;
    public const uint Int4 = 23;
    public const uint Text = 25;
    public const uint Oid = 26;
    public const uint Json = 114;
    public const uint Xml = 142;
    public const uint Float4 = 700;
    public const uint Float8 = 701;
    public const uint Unknown = 705;
    public const uint Bpchar = 1042;
    public const uint Varchar = 1043;
    public const uint Date = 1082;
    public const uint Time = 1083;
    public const uint Timestamp = 1114;
    public const uint TimestampTz = 1184;
    public const uint Interval = 1186;
    public const uint TimeTz = 1266;
    public const uint Numeric = 1700;
    public const uint Uuid = 2950;
    public const uint Jsonb = 3802;

    // Array OIDs (typarray column in pg_type).
    public const uint BoolArray = 1000;
    public const uint ByteaArray = 1001;
    public const uint Int2Array = 1005;
    public const uint Int4Array = 1007;
    public const uint TextArray = 1009;
    public const uint VarcharArray = 1015;
    public const uint Int8Array = 1016;
    public const uint Float4Array = 1021;
    public const uint Float8Array = 1022;
    public const uint UuidArray = 2951;
    public const uint NumericArray = 1231;
    public const uint TimestampArray = 1115;
    public const uint TimestampTzArray = 1185;
    public const uint DateArray = 1182;
    public const uint JsonArray = 199;
    public const uint JsonbArray = 3807;
}
