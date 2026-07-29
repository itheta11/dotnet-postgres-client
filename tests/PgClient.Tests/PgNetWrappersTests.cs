using System.Data;
using System.Data.Common;
using PgClient.PgNet;
using Xunit;

namespace PgClient.Tests;

public class PgNetWrappersTests
{
    [Fact]
    public void PgDbProviderFactory_CreatesEachType()
    {
        var f = PgDbProviderFactory.Instance;
        Assert.IsType<PgDbConnection>(f.CreateConnection());
        Assert.IsType<PgDbCommand>(f.CreateCommand());
        Assert.IsType<PgDbParameter>(f.CreateParameter());
    }

    [Fact]
    public void PgDbConnection_ParsesConnectionString()
    {
        var conn = new PgDbConnection("Host=example.com;Port=5432;Username=u;Database=d");
        Assert.Equal("d", conn.Database);
        Assert.Equal("example.com", conn.DataSource);
        Assert.Equal(ConnectionState.Closed, conn.State);
    }

    [Fact]
    public void PgDbParameter_DefaultsToObjectDbType()
    {
        var p = new PgDbParameter("@id", 7);
        Assert.Equal(DbType.Object, p.DbType);
        Assert.Equal("@id", p.ParameterName);
        Assert.Equal(7, p.Value);
    }

    [Fact]
    public void PgDbParameterCollection_AddAndLookup()
    {
        var col = new PgDbParameterCollection();
        var p1 = new PgDbParameter("id", 1);
        var p2 = new PgDbParameter("name", "abc");
        col.Add(p1);
        col.Add(p2);
        Assert.Equal(2, col.Count);
        Assert.Equal(1, col.IndexOf("Name"));  // case-insensitive lookup
        Assert.Same(p1, col["id"]);
    }

    [Fact]
    public void PgDbCommand_CreatesParameter()
    {
        var cmd = new PgDbCommand("SELECT $1");
        var p = cmd.CreateParameter();
        Assert.IsType<PgDbParameter>(p);
    }
}
