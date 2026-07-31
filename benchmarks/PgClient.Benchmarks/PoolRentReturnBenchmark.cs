using BenchmarkDotNet.Attributes;
using PgClient;
using PgClient.Pool;

namespace PgClientBenchmarks;

/// Measures the hot path of renting and returning a connection to a warm pool.
/// The pool is pre-warmed so this excludes physical connection setup and
/// focuses on synchronisation + `DISCARD ALL` reset cost.
[MemoryDiagnoser]
public class PoolRentReturnBenchmark
{
    private PgConnectionPool _pool = default!;

    [Params(false, true)]
    public bool NoResetOnClose { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        var parameters = BenchmarkConfig.Build("PgClient.Bench.Pool");
        parameters.MinPoolSize = 4;
        parameters.MaxPoolSize = 8;
        parameters.NoResetOnClose = NoResetOnClose;
        _pool = new PgConnectionPool(parameters);

        // Prime the pool by renting/returning once.
        await using var conn = await _pool.RentAsync();
    }

    [GlobalCleanup]
    public async Task Cleanup() => await _pool.DisposeAsync();

    [Benchmark]
    public async Task RentAndReturn()
    {
        await using var conn = await _pool.RentAsync();
    }
}
