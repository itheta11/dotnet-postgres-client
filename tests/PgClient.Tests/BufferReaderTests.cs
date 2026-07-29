using System.Text;
using PgClient.BufferUtils;
using Xunit;

namespace PgClient.Tests;

public class BufferReaderTests
{
    [Fact]
    public void ReadByte_AdvancesOffset()
    {
        var r = new BufferReader();
        r.SetBuffer(new byte[] { 0x01, 0x02, 0x03 });
        Assert.Equal(0x01, r.ReadByte());
        Assert.Equal(0x02, r.ReadByte());
        Assert.Equal(1, r.Remaining);
        Assert.Equal(2, r.Position);
    }

    [Fact]
    public void ReadInt16_BigEndian()
    {
        var r = new BufferReader();
        r.SetBuffer(new byte[] { 0x01, 0x02 });
        Assert.Equal((short)0x0102, r.ReadInt16());
    }

    [Fact]
    public void ReadInt32_BigEndian()
    {
        var r = new BufferReader();
        r.SetBuffer(new byte[] { 0x00, 0x00, 0x03, 0x00 });
        Assert.Equal(768, r.ReadInt32());
    }

    [Fact]
    public void ReadUInt32_BigEndian_Full()
    {
        var r = new BufferReader();
        r.SetBuffer(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF });
        Assert.Equal(uint.MaxValue, r.ReadUInt32());
    }

    [Fact]
    public void ReadCString_ReadsUntilNull()
    {
        var bytes = Encoding.UTF8.GetBytes("hello\0world\0");
        var r = new BufferReader();
        r.SetBuffer(bytes);
        Assert.Equal("hello", r.ReadCString());
        Assert.Equal("world", r.ReadCString());
    }

    [Fact]
    public void ReadCString_UnterminatedThrows()
    {
        var r = new BufferReader();
        r.SetBuffer(Encoding.UTF8.GetBytes("no-null"));
        Assert.Throws<InvalidOperationException>(() => r.ReadCString());
    }

    [Fact]
    public void ReadString_LengthPrefixed()
    {
        var bytes = new byte[] { 0x00, 0x00, 0x00, 0x05, (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o' };
        var r = new BufferReader();
        r.SetBuffer(bytes);
        Assert.Equal("hello", r.ReadString());
    }

    [Fact]
    public void ReadString_MinusOneReturnsNull()
    {
        var bytes = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF };
        var r = new BufferReader();
        r.SetBuffer(bytes);
        Assert.Null(r.ReadString());
    }

    [Fact]
    public void ReadBytes_ReturnsExactSlice()
    {
        var r = new BufferReader();
        r.SetBuffer(new byte[] { 1, 2, 3, 4, 5 });
        r.Skip(1);
        var slice = r.ReadBytes(3);
        Assert.Equal(3, slice.Length);
        Assert.Equal(2, slice[0]);
        Assert.Equal(3, slice[1]);
        Assert.Equal(4, slice[2]);
        Assert.Equal(1, r.Remaining);
    }

    [Fact]
    public void Ensure_ThrowsWhenExhausted()
    {
        var r = new BufferReader();
        r.SetBuffer(new byte[] { 0x01 });
        r.ReadByte();
        Assert.Throws<InvalidOperationException>(() => r.ReadByte());
    }

    [Fact]
    public void Reset_ReturnsToStart()
    {
        var r = new BufferReader();
        r.SetBuffer(new byte[] { 1, 2, 3 });
        r.ReadByte();
        r.Reset();
        Assert.Equal(0, r.Position);
        Assert.Equal(1, r.ReadByte());
    }
}
