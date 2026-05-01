using System;
using BenchmarkDotNet.Attributes;

namespace PgClient.Benchmark;

[MemoryDiagnoser]
public class Benchmark
{
    [Benchmark]
    public async Task AnalysePgClient()
    {
        ConnectionParameters connectionParameters = new ConnectionParameters()
        {
            Hostname = "172.17.0.1",
            Port = 5432,
            Username = "admin",
            Password = "",
            Database = "movie",
            ApplicationName = "",
            FallbackApplicationName = "",
        };
        using PgConnection pgConnection = new PgConnection(connectionParameters);
        await pgConnection.ConnectAsync();
        string query = "SELECT * FROM Movies";
        await foreach (var row in pgConnection.ExecuteReaderAsync(query))
        {
            //Console.WriteLine(string.Join(", ", row));
        }
        //var res = pgConnection.ExecuteQuery("Select * from Movies");
        pgConnection.Close();

    }
}
