using System.Text;
using PgClient.Response;
using Xunit;

namespace PgClient.Tests;

public class PgErrorInfoTests
{
    [Fact]
    public void Parse_ExtractsAllStandardFields()
    {
        byte[] payload = BuildPayload(new (char code, string val)[]
        {
            ('S', "ERROR"),
            ('V', "ERROR"),
            ('C', "42P01"),
            ('M', "relation \"movies\" does not exist"),
            ('D', "detail line"),
            ('H', "did you mean 'movie'?"),
            ('P', "15"),
            ('W', "PL/pgSQL function foo() line 3"),
            ('s', "public"),
            ('t', "movies"),
            ('c', "movieid"),
            ('d', "integer"),
            ('n', "movies_pkey"),
            ('F', "parse_relation.c"),
            ('L', "1163"),
            ('R', "parserOpenTable"),
        });

        var info = PgErrorInfo.Parse(payload);

        Assert.Equal("ERROR", info.Severity);
        Assert.Equal("ERROR", info.SeverityNonLocalized);
        Assert.Equal("42P01", info.SqlState);
        Assert.Equal("relation \"movies\" does not exist", info.Message);
        Assert.Equal("detail line", info.Detail);
        Assert.Equal("did you mean 'movie'?", info.Hint);
        Assert.Equal("15", info.Position);
        Assert.Equal("PL/pgSQL function foo() line 3", info.Where);
        Assert.Equal("public", info.SchemaName);
        Assert.Equal("movies", info.TableName);
        Assert.Equal("movieid", info.ColumnName);
        Assert.Equal("integer", info.DataTypeName);
        Assert.Equal("movies_pkey", info.ConstraintName);
        Assert.Equal("parse_relation.c", info.File);
        Assert.Equal("1163", info.Line);
        Assert.Equal("parserOpenTable", info.Routine);
    }

    [Fact]
    public void Parse_UnknownFieldCodes_AreIgnored()
    {
        byte[] payload = BuildPayload(new (char code, string val)[]
        {
            ('X', "unknown"),
            ('M', "hello"),
        });

        var info = PgErrorInfo.Parse(payload);

        Assert.Equal("hello", info.Message);
        Assert.Null(info.Severity);
    }

    [Fact]
    public void Parse_EmptyPayload_ReturnsEmptyInfo()
    {
        var info = PgErrorInfo.Parse(ReadOnlySpan<byte>.Empty);
        Assert.Null(info.Message);
        Assert.Null(info.SqlState);
    }

    [Fact]
    public void PgException_MessageFromErrorInfo()
    {
        var info = new PgErrorInfo { Message = "boom", SqlState = "XX000" };
        var ex = new PgException(info);
        Assert.Equal("boom", ex.Message);
        Assert.Equal("XX000", ex.SqlState);
    }

    [Fact]
    public void PgException_FromErrorResponse_ParsesPayload()
    {
        byte[] payload = BuildPayload(new (char code, string val)[]
        {
            ('S', "ERROR"),
            ('C', "23505"),
            ('M', "duplicate key"),
        });

        var ex = PgException.FromErrorResponse(payload);

        Assert.Equal("duplicate key", ex.Message);
        Assert.Equal("23505", ex.SqlState);
    }

    private static byte[] BuildPayload((char code, string val)[] fields)
    {
        using var ms = new MemoryStream();
        foreach (var (code, val) in fields)
        {
            ms.WriteByte((byte)code);
            byte[] bytes = Encoding.UTF8.GetBytes(val);
            ms.Write(bytes, 0, bytes.Length);
            ms.WriteByte(0);
        }
        ms.WriteByte(0); // terminator
        return ms.ToArray();
    }
}
