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
            Hostname = "aws-1-ap-south-1.pooler.supabase.com",
            Port = 5432,
            Username = "postgres.sjdxtmfvjsodboienfdy",
            Password = "Anupadmin123@#",
            Database = "postgres",
            ApplicationName = "pgclient",
            FallbackApplicationName = "pgclient",
        };
        using PgConnection pgConnection = new PgConnection(connectionParameters);
        await pgConnection.ConnectAsync();
        var res = pgConnection.ExecuteQuery("Select * from \"Movie\"");
        pgConnection.Close();
    }
}
