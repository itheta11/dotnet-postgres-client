using BenchmarkDotNet.Attributes;
using PgClient;

namespace PgClientBenchmarks;

[MemoryDiagnoser]
public class SimpleQueryBenchmark
{
    private PgConnection? _connection;

    [Params("SELECT 1", "SELECT generate_series(1, 100)")]
    public string Sql { get; set; } = "SELECT 1";

    [GlobalSetup]
    public async Task Setup()
    {
        var parameters = new ConnectionParameters
        {
            Hostname = Environment.GetEnvironmentVariable("PGHOST") ?? "localhost",
            Port = int.TryParse(Environment.GetEnvironmentVariable("PGPORT"), out var p) ? p : 5432,
            Username = Environment.GetEnvironmentVariable("PGUSER") ?? "postgres",
            Password = Environment.GetEnvironmentVariable("PGPASSWORD") ?? string.Empty,
            Database = Environment.GetEnvironmentVariable("PGDATABASE") ?? "postgres",
            ApplicationName = "PgClient.Benchmarks",
        };
        _connection = new PgConnection(parameters);
        await _connection.ConnectAsync();
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        if (_connection is not null) await _connection.DisposeAsync();
    }

    [Benchmark]
    public async Task RunQuery()
    {
        await using var reader = await _connection!.ExecuteReaderAsync(Sql);
        while (await reader.ReadAsync()) { }
    }
}
