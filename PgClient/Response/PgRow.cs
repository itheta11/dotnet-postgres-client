using System;

namespace PgClient.Response;

public class PgRow
{
    public string Name { get; set; }
    public int TableOid { get; set; }

    public short ColumnAttribute { get; set; }
    public int TypeOid { get; set; }
    public short TypeSize { get; set; }
    public int TypeModifier { get; set; }
    public string FormatCode { get; set; }

}
