using System.Text;
using PgClient.Response;
using Xunit;

namespace PgClient.Tests;

public class CommandTagTests
{
    [Theory]
    [InlineData("SELECT 10", "SELECT", 0u, 10L)]
    [InlineData("UPDATE 3", "UPDATE", 0u, 3L)]
    [InlineData("DELETE 2", "DELETE", 0u, 2L)]
    [InlineData("COPY 100", "COPY", 0u, 100L)]
    [InlineData("MOVE 5", "MOVE", 0u, 5L)]
    [InlineData("FETCH 7", "FETCH", 0u, 7L)]
    public void Parse_TwoTokenTags(string tag, string op, uint expectedOid, long expectedRows)
    {
        var t = CommandTag.ParseTag(tag);
        Assert.Equal(op, t.Operation);
        Assert.Equal(expectedOid, t.InsertOid);
        Assert.Equal(expectedRows, t.RowsAffected);
    }

    [Fact]
    public void Parse_InsertTag_ExtractsOidAndRows()
    {
        var t = CommandTag.ParseTag("INSERT 12345 42");
        Assert.Equal("INSERT", t.Operation);
        Assert.Equal(12345u, t.InsertOid);
        Assert.Equal(42L, t.RowsAffected);
    }

    [Theory]
    [InlineData("BEGIN", "BEGIN", -1L)]
    [InlineData("COMMIT", "COMMIT", -1L)]
    [InlineData("SET", "SET", -1L)]
    [InlineData("CREATE TABLE", "CREATE", -1L)]
    public void Parse_UnaryOrKeywordTags(string tag, string op, long expectedRows)
    {
        var t = CommandTag.ParseTag(tag);
        Assert.Equal(op, t.Operation);
        Assert.Equal(expectedRows, t.RowsAffected);
    }

    [Fact]
    public void Parse_FromPayload_HandlesNullTerminator()
    {
        byte[] payload = Encoding.ASCII.GetBytes("SELECT 5\0");
        var t = CommandTag.Parse(payload);
        Assert.Equal("SELECT", t.Operation);
        Assert.Equal(5L, t.RowsAffected);
    }

    [Fact]
    public void Parse_EmptyPayload_ReturnsEmpty()
    {
        var t = CommandTag.Parse(ReadOnlySpan<byte>.Empty);
        Assert.Equal(string.Empty, t.Operation);
        Assert.Equal(-1L, t.RowsAffected);
    }
}
