using BenchmarkDotNet.Attributes;
using PgClient;
using PgClient.Query;

namespace PgClientBenchmarks;

/// Measures the extended-query protocol path (Parse/Bind/Describe/Execute/Sync)
/// with auto-preparation, exercising the prepared-statement cache after warmup.
[MemoryDiagnoser]
public class ExtendedQueryBenchmark
{
    private PgConnection _connection = default!;
    private readonly PgParameter[] _parameters = { new PgParameter(42) };

    private const string Sql = "SELECT $1::int";

    [GlobalSetup]
    public async Task Setup()
    {
        var connParams = BenchmarkConfig.Build("PgClient.Bench.Extended");
        connParams.AutoPrepareMinUsages = 1;
        _connection = new PgConnection(connParams);
        await _connection.ConnectAsync();

        // Warm the prepared cache.
        for (int i = 0; i < 3; i++)
        {
            await using var r = await _connection.ExecuteReaderAsync(Sql, _parameters);
            while (await r.ReadAsync()) { }
        }
    }

    [GlobalCleanup]
    public async Task Cleanup() => await _connection.DisposeAsync();

    [Benchmark]
    public async Task<int> ExecuteParameterized()
    {
        int rows = 0;
        await using var reader = await _connection.ExecuteReaderAsync(Sql, _parameters);
        while (await reader.ReadAsync()) rows++;
        return rows;
    }
}
