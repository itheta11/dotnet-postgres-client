using BenchmarkDotNet.Attributes;
using PgClient;

namespace PgClientBenchmarks;

/// Measures throughput of streaming many rows through the data reader, exercising
/// the buffer-reader and text-decoding hot paths.
[MemoryDiagnoser]
public class MultiRowReadBenchmark
{
    private PgConnection _connection = default!;

    [Params(100, 1_000, 10_000)]
    public int RowCount { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        _connection = new PgConnection(BenchmarkConfig.Build("PgClient.Bench.MultiRow"));
        await _connection.ConnectAsync();
    }

    [GlobalCleanup]
    public async Task Cleanup() => await _connection.DisposeAsync();

    [Benchmark]
    public async Task<long> ReadRows()
    {
        long sum = 0;
        await using var reader = await _connection.ExecuteReaderAsync(
            $"SELECT generate_series(1, {RowCount})");
        while (await reader.ReadAsync())
        {
            sum += reader.GetInt32(0);
        }
        return sum;
    }
}
