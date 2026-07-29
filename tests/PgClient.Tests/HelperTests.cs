using System.Buffers.Binary;
using PgClient.Utilities;
using Xunit;

namespace PgClient.Tests;

public class HelperTests
{
    [Fact]
    public void WriteInt32BE_Span_WritesBigEndian()
    {
        Span<byte> buf = stackalloc byte[4];
        Helper.WriteInt32BE(buf, 0x01020304);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, buf.ToArray());
    }

    [Fact]
    public void WriteInt32BE_Stream_RoundTrips()
    {
        var ms = new MemoryStream();
        Helper.WriteInt32BE(ms, 196608);
        ms.Position = 0;
        Assert.Equal(196608, Helper.ReadInt32BE(ms));
    }

    [Fact]
    public void WriteInt32BE_BinaryWriter_RoundTrips()
    {
        var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            Helper.WriteInt32BE(w, -1);
        }
        ms.Position = 0;
        using var r = new BinaryReader(ms);
        Assert.Equal(-1, Helper.ReadInt32BE(r));
    }

    [Fact]
    public void WriteCString_TerminatesWithZero()
    {
        var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            Helper.WriteCString(w, "hello");
        }
        var bytes = ms.ToArray();
        Assert.Equal(6, bytes.Length);
        Assert.Equal((byte)'h', bytes[0]);
        Assert.Equal(0, bytes[5]);
    }

    [Fact]
    public void ToBigEndian_ReversesBytes()
    {
        int swapped = Helper.ToBigEndian(0x01020304);
        Assert.Equal(unchecked((int)0x04030201), swapped);
    }

    [Fact]
    public void WriteCString_LargePayload_UsesArrayPoolPath()
    {
        string big = new string('a', 4096);
        var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            Helper.WriteCString(w, big);
        }
        var bytes = ms.ToArray();
        Assert.Equal(4097, bytes.Length);
        Assert.Equal(0, bytes[^1]);
    }
}
