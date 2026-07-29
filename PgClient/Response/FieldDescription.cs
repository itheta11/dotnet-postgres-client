namespace PgClient.Response;

/// A single column description from a Postgres RowDescription (T) message.
public sealed class FieldDescription
{
    public string Name { get; init; } = string.Empty;
    public uint TableOid { get; init; }
    public short ColumnAttributeNumber { get; init; }
    public uint TypeOid { get; init; }
    public short TypeSize { get; init; }
    public int TypeModifier { get; init; }
    public PgFormatCode FormatCode { get; init; }
}

public enum PgFormatCode : short
{
    Text = 0,
    Binary = 1,
}
