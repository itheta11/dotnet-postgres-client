using BenchmarkDotNet.Attributes;
using PgClient;

namespace PgClientBenchmarks;

/// Measures the end-to-end cost of opening (TCP + startup + auth + parameter
/// negotiation) and cleanly closing a single connection.
[MemoryDiagnoser]
public class ConnectionOpenBenchmark
{
    private ConnectionParameters _parameters = default!;

    [GlobalSetup]
    public void Setup() => _parameters = BenchmarkConfig.Build("PgClient.Bench.Open");

    [Benchmark]
    public async Task OpenAndClose()
    {
        await using var connection = new PgConnection(_parameters);
        await connection.ConnectAsync();
    }
}
