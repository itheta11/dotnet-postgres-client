using PgClient.Query;
using PgClient.Response;
using PgClient.Types;
using Xunit;

namespace PgClient.Tests;

public class PgParameterTests
{
    [Fact]
    public void Factory_Int4_SetsOid()
    {
        var p = PgParameter.Int4(42);
        Assert.Equal(PgOid.Int4, p.TypeOid);
        Assert.Equal(42, p.Value);
        Assert.Equal(PgFormatCode.Text, p.FormatCode);
    }

    [Fact]
    public void Encode_NullValue_ReturnsNull()
    {
        var p = PgParameter.Null(PgOid.Text);
        Assert.Null(p.Encode(PgTypeRegistry.Default));
    }

    [Fact]
    public void Encode_Int4_Text_ProducesAsciiDigits()
    {
        var p = PgParameter.Int4(12345);
        var bytes = p.Encode(PgTypeRegistry.Default);
        Assert.Equal(System.Text.Encoding.ASCII.GetBytes("12345"), bytes);
    }

    [Fact]
    public void Encode_Text_Utf8()
    {
        var p = PgParameter.Text("hé");
        var bytes = p.Encode(PgTypeRegistry.Default);
        Assert.Equal(System.Text.Encoding.UTF8.GetBytes("hé"), bytes);
    }

    [Fact]
    public void Encode_WithoutExplicitOid_InfersFromClrType()
    {
        var p = new PgParameter(1234);
        var bytes = p.Encode(PgTypeRegistry.Default);
        Assert.Equal(PgOid.Int4, p.TypeOid);
        Assert.Equal(System.Text.Encoding.ASCII.GetBytes("1234"), bytes);
    }

    [Fact]
    public void Encode_Int4_Binary_ProducesBigEndianBytes()
    {
        var p = new PgParameter(0x01020304, PgOid.Int4, PgFormatCode.Binary);
        var bytes = p.Encode(PgTypeRegistry.Default);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, bytes);
    }
}
