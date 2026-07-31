using PgClient;

namespace PgClientBenchmarks;

/// Shared helpers for benchmark connection parameters read from environment.
internal static class BenchmarkConfig
{
    public static ConnectionParameters Build(string appName)
    {
        return new ConnectionParameters
        {
            Hostname = Environment.GetEnvironmentVariable("PGHOST") ?? "localhost",
            Port = int.TryParse(Environment.GetEnvironmentVariable("PGPORT"), out var p) ? p : 5432,
            Username = Environment.GetEnvironmentVariable("PGUSER") ?? "postgres",
            Password = Environment.GetEnvironmentVariable("PGPASSWORD") ?? string.Empty,
            Database = Environment.GetEnvironmentVariable("PGDATABASE") ?? "postgres",
            ApplicationName = appName,
        };
    }
}
