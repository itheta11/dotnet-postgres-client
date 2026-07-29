using System.Data;
using PgClient.Response;

namespace PgClient.PgNet;

/// Maps between <see cref="DbType"/> and Postgres type OIDs.
internal static class Types
{
    public static uint PgTypeOidFromDbType(DbType dbType) => dbType switch
    {
        DbType.Boolean => PgOid.Bool,
        DbType.Int16 => PgOid.Int2,
        DbType.Int32 => PgOid.Int4,
        DbType.Int64 => PgOid.Int8,
        DbType.Single => PgOid.Float4,
        DbType.Double => PgOid.Float8,
        DbType.Decimal => PgOid.Numeric,
        DbType.Currency => PgOid.Numeric,
        DbType.VarNumeric => PgOid.Numeric,
        DbType.String => PgOid.Text,
        DbType.StringFixedLength => PgOid.Bpchar,
        DbType.AnsiString => PgOid.Text,
        DbType.AnsiStringFixedLength => PgOid.Bpchar,
        DbType.Guid => PgOid.Uuid,
        DbType.Binary => PgOid.Bytea,
        DbType.Byte => PgOid.Int2,
        DbType.Date => PgOid.Date,
        DbType.Time => PgOid.Time,
        DbType.DateTime => PgOid.Timestamp,
        DbType.DateTime2 => PgOid.Timestamp,
        DbType.DateTimeOffset => PgOid.TimestampTz,
        _ => 0, // unspecified
    };

    public static Type PgClrTypeFromOid(uint oid) => oid switch
    {
        PgOid.Bool => typeof(bool),
        PgOid.Int2 => typeof(short),
        PgOid.Int4 => typeof(int),
        PgOid.Int8 => typeof(long),
        PgOid.Float4 => typeof(float),
        PgOid.Float8 => typeof(double),
        PgOid.Numeric => typeof(decimal),
        PgOid.Uuid => typeof(Guid),
        PgOid.Bytea => typeof(byte[]),
        PgOid.Date => typeof(DateTime),
        PgOid.Timestamp or PgOid.TimestampTz => typeof(DateTime),
        _ => typeof(string),
    };
}
