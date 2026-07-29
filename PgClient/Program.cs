using PgClient;

var parameters = new ConnectionParameters
{
    Hostname = "localhost",
    Port = 5432,
    Username = "admin",
    Password = "anup",
    Database = "movie",
    ApplicationName = "PgClientSample",
    FallbackApplicationName = "",
};

await using var connection = new PgConnection(parameters);
connection.Notice += n => Console.WriteLine($"NOTICE: {n}");

await connection.ConnectAsync();

const string query = "SELECT * FROM Movies ORDER BY movieid LIMIT 10;";
await using (var reader = await connection.ExecuteReaderAsync(query))
{
    for (int i = 0; i < reader.FieldCount; i++)
    {
        Console.Write(reader.GetName(i));
        Console.Write(i == reader.FieldCount - 1 ? "\n" : "\t");
    }

    while (await reader.ReadAsync())
    {
        for (int i = 0; i < reader.FieldCount; i++)
        {
            Console.Write(reader.IsDBNull(i) ? "NULL" : reader.GetString(i));
            Console.Write(i == reader.FieldCount - 1 ? "\n" : "\t");
        }
    }

    Console.WriteLine($"Command tag: {reader.CommandTag.Operation} rows={reader.CommandTag.RowsAffected}");
}

Console.WriteLine("Completed");
