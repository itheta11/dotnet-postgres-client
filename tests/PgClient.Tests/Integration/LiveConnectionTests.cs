using PgClient;
using PgClient.Response;
using Xunit;

namespace PgClient.Tests.Integration;

/// Live end-to-end tests against a real Postgres instance.
///
/// Skipped unless the environment variable <c>PGCLIENT_TEST_CONN</c> is set in
/// the form: <c>host;port;user;password;database</c>. Example:
///   export PGCLIENT_TEST_CONN="localhost;5432;admin;anup;movie"
public class LiveConnectionTests
{
    private const string ConnEnvVar = "PGCLIENT_TEST_CONN";

    public static bool ShouldRun => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(ConnEnvVar));

    private static ConnectionParameters BuildParameters()
    {
        var raw = Environment.GetEnvironmentVariable(ConnEnvVar)!;
        var parts = raw.Split(';');
        if (parts.Length != 5)
            throw new InvalidOperationException($"{ConnEnvVar} must be host;port;user;password;database");

        return new ConnectionParameters
        {
            Hostname = parts[0],
            Port = int.Parse(parts[1]),
            Username = parts[2],
            Password = parts[3],
            Database = parts[4],
            ApplicationName = "PgClient.Tests",
            FallbackApplicationName = "",
        };
    }

    [SkippableFact]
    public async Task Connect_And_SelectOne_Works()
    {
        Skip.IfNot(ShouldRun, $"Set {ConnEnvVar} to run live tests.");

        await using var conn = new PgConnection(BuildParameters());
        await conn.ConnectAsync();

        await using var reader = await conn.ExecuteReaderAsync("SELECT 1;");
        Assert.True(await reader.ReadAsync());
        Assert.Equal(1, reader.GetInt32(0));
        Assert.False(await reader.ReadAsync());
        Assert.Equal("SELECT", reader.CommandTag.Operation);
        Assert.Equal(1L, reader.CommandTag.RowsAffected);
    }

    [SkippableFact]
    public async Task ExecuteScalar_ReturnsFirstColumnOfFirstRow()
    {
        Skip.IfNot(ShouldRun, $"Set {ConnEnvVar} to run live tests.");

        await using var conn = new PgConnection(BuildParameters());
        await conn.ConnectAsync();

        var result = await conn.ExecuteScalarAsync("SELECT 42;");
        Assert.Equal(42, result);
    }

    [SkippableFact]
    public async Task ExecuteNonQuery_ReturnsCommandTag()
    {
        Skip.IfNot(ShouldRun, $"Set {ConnEnvVar} to run live tests.");

        await using var conn = new PgConnection(BuildParameters());
        await conn.ConnectAsync();

        // Use a session-only temp table so we do not require write privileges.
        await conn.ExecuteNonQueryAsync("CREATE TEMP TABLE t_pgclient_test(id int);");
        var tag = await conn.ExecuteNonQueryAsync("INSERT INTO t_pgclient_test(id) VALUES (1),(2),(3);");

        Assert.Equal("INSERT", tag.Operation);
        Assert.Equal(3L, tag.RowsAffected);
    }

    [SkippableFact]
    public async Task InvalidQuery_ThrowsPgException_WithSqlState()
    {
        Skip.IfNot(ShouldRun, $"Set {ConnEnvVar} to run live tests.");

        await using var conn = new PgConnection(BuildParameters());
        await conn.ConnectAsync();

        var ex = await Assert.ThrowsAsync<PgException>(async () =>
        {
            await using var r = await conn.ExecuteReaderAsync("SELECT * FROM this_table_does_not_exist;");
            while (await r.ReadAsync()) { }
        });

        Assert.False(string.IsNullOrEmpty(ex.SqlState));
        Assert.Equal("42P01", ex.SqlState);
    }
}
