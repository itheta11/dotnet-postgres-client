using PgClient.Response;
using PgClient.Types;
using PgClient.Types.Handlers;
using Xunit;

namespace PgClient.Tests;

public class TypeHandlerTests
{
    [Fact]
    public void BoolHandler_TextRoundTrip()
    {
        var h = new BoolHandler();
        Assert.Equal(true, h.ReadText(h.EncodeText(true)));
        Assert.Equal(false, h.ReadText(h.EncodeText(false)));
    }

    [Fact]
    public void BoolHandler_BinaryRoundTrip()
    {
        var h = new BoolHandler();
        Assert.Equal(true, h.ReadBinary(h.EncodeBinary(true)));
        Assert.Equal(false, h.ReadBinary(h.EncodeBinary(false)));
    }

    [Theory]
    [InlineData((short)0)]
    [InlineData((short)-32768)]
    [InlineData((short)32767)]
    public void Int2Handler_BinaryRoundTrip(short value)
    {
        var h = new Int2Handler();
        Assert.Equal(value, h.ReadBinary(h.EncodeBinary(value)));
        Assert.Equal(value, h.ReadText(h.EncodeText(value)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    public void Int4Handler_BinaryRoundTrip(int value)
    {
        var h = new Int4Handler();
        Assert.Equal(value, h.ReadBinary(h.EncodeBinary(value)));
        Assert.Equal(value, h.ReadText(h.EncodeText(value)));
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(long.MinValue)]
    [InlineData(long.MaxValue)]
    public void Int8Handler_BinaryRoundTrip(long value)
    {
        var h = new Int8Handler();
        Assert.Equal(value, h.ReadBinary(h.EncodeBinary(value)));
        Assert.Equal(value, h.ReadText(h.EncodeText(value)));
    }

    [Fact]
    public void Float4Handler_BinaryRoundTrip()
    {
        var h = new Float4Handler();
        float v = 3.14f;
        Assert.Equal(v, (float)h.ReadBinary(h.EncodeBinary(v)));
    }

    [Fact]
    public void Float8Handler_BinaryRoundTrip()
    {
        var h = new Float8Handler();
        double v = Math.PI;
        Assert.Equal(v, (double)h.ReadBinary(h.EncodeBinary(v)));
    }

    [Fact]
    public void TextHandler_TextRoundTrip_Unicode()
    {
        var h = new TextHandler(PgOid.Text);
        string s = "café — 日本語";
        Assert.Equal(s, h.ReadText(h.EncodeText(s)));
    }

    [Fact]
    public void UuidHandler_BinaryRoundTrip()
    {
        var h = new UuidHandler();
        var g = Guid.NewGuid();
        Assert.Equal(g, h.ReadBinary(h.EncodeBinary(g)));
    }

    [Fact]
    public void UuidHandler_TextRoundTrip()
    {
        var h = new UuidHandler();
        var g = Guid.NewGuid();
        Assert.Equal(g, h.ReadText(h.EncodeText(g)));
    }

    [Fact]
    public void ByteaHandler_HexTextRoundTrip()
    {
        var h = new ByteaHandler();
        byte[] value = { 0x00, 0x01, 0xff, 0xab, 0xcd };
        var text = h.EncodeText(value);
        var back = (byte[])h.ReadText(text);
        Assert.Equal(value, back);
    }

    [Fact]
    public void ByteaHandler_BinaryRoundTrip()
    {
        var h = new ByteaHandler();
        byte[] value = { 0x00, 0x01, 0xff, 0xab, 0xcd };
        Assert.Equal(value, h.ReadBinary(h.EncodeBinary(value)));
    }

    [Fact]
    public void Registry_LookupByOid_ReturnsExpected()
    {
        var r = PgTypeRegistry.Default;
        Assert.NotNull(r.Get(PgOid.Bool));
        Assert.NotNull(r.Get(PgOid.Int4));
        Assert.NotNull(r.Get(PgOid.Text));
        Assert.NotNull(r.Get(PgOid.Uuid));
        Assert.Null(r.Get(9999999u));
    }

    [Fact]
    public void Registry_LookupByClrType_ReturnsExpected()
    {
        var r = PgTypeRegistry.Default;
        Assert.Equal(PgOid.Int4, r.GetForClrType(typeof(int))!.TypeOid);
        Assert.Equal(PgOid.Int8, r.GetForClrType(typeof(long))!.TypeOid);
        Assert.Equal(PgOid.Bool, r.GetForClrType(typeof(bool))!.TypeOid);
        Assert.Equal(PgOid.Uuid, r.GetForClrType(typeof(Guid))!.TypeOid);
    }
}
