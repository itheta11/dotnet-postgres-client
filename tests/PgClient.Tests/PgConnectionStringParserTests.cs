using PgClient;
using PgClient.Ssl;
using Xunit;

namespace PgClient.Tests;

public class PgConnectionStringParserTests
{
    [Fact]
    public void ParsesRequiredKeys()
    {
        var p = PgConnectionStringParser.Parse("Host=localhost;Port=5433;Username=alice;Database=movies");
        Assert.Equal("localhost", p.Hostname);
        Assert.Equal(5433, p.Port);
        Assert.Equal("alice", p.Username);
        Assert.Equal("movies", p.Database);
    }

    [Fact]
    public void MissingRequiredKey_Throws()
    {
        Assert.Throws<FormatException>(() =>
            PgConnectionStringParser.Parse("Port=5432;Username=x;Database=y"));
    }

    [Fact]
    public void AcceptsAliases()
    {
        var p = PgConnectionStringParser.Parse("Server=db;Port=5432;User Id=bob;Password=s3cret;Db=app");
        Assert.Equal("db", p.Hostname);
        Assert.Equal("bob", p.Username);
        Assert.Equal("s3cret", p.Password);
        Assert.Equal("app", p.Database);
    }

    [Fact]
    public void ParsesSslMode()
    {
        var p = PgConnectionStringParser.Parse(
            "Host=h;Port=5432;Username=u;Database=d;SSL Mode=VerifyFull;Trust Server Certificate=true");
        Assert.Equal(SslMode.VerifyFull, p.SslMode);
        Assert.True(p.TrustServerCertificate);
    }

    [Fact]
    public void ParsesPoolSettings()
    {
        var p = PgConnectionStringParser.Parse(
            "Host=h;Port=5432;Username=u;Database=d;Maximum Pool Size=50;Minimum Pool Size=5;Connection Idle Lifetime=120");
        Assert.Equal(50, p.MaxPoolSize);
        Assert.Equal(5, p.MinPoolSize);
        Assert.Equal(TimeSpan.FromSeconds(120), p.ConnectionIdleLifetime);
    }

    [Fact]
    public void ParsesQuotedValueContainingSemicolon()
    {
        var p = PgConnectionStringParser.Parse(
            "Host=h;Port=5432;Username=u;Database=d;Password=\"a;b=c\"");
        Assert.Equal("a;b=c", p.Password);
    }

    [Fact]
    public void ParsesTimeoutSeconds()
    {
        var p = PgConnectionStringParser.Parse(
            "Host=h;Port=5432;Username=u;Database=d;Timeout=7;Command Timeout=45");
        Assert.Equal(TimeSpan.FromSeconds(7), p.ConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(45), p.CommandTimeout);
    }

    [Fact]
    public void ToConnectionString_RoundTripsCoreFields()
    {
        var original = new ConnectionParameters
        {
            Hostname = "h",
            Port = 6543,
            Username = "u",
            Database = "d",
            SslMode = SslMode.Require,
            MaxPoolSize = 32,
        };
        string cs = PgConnectionStringParser.ToConnectionString(original);
        var round = PgConnectionStringParser.Parse(cs);
        Assert.Equal(original.Hostname, round.Hostname);
        Assert.Equal(original.Port, round.Port);
        Assert.Equal(original.Username, round.Username);
        Assert.Equal(original.Database, round.Database);
        Assert.Equal(original.SslMode, round.SslMode);
        Assert.Equal(original.MaxPoolSize, round.MaxPoolSize);
    }
}
