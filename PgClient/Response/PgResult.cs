using System;

namespace PgClient.Response;

public class PgResult
{
    public List<PgRow> Columns { get; set; } = new();
    public List<List<string>> Rows { get; set; } = new();

    public string? CommandTag { get; set; }
}
