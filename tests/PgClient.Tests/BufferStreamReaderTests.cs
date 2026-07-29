using System.Buffers.Binary;
using System.Text;
using PgClient.BufferUtils;
using Xunit;

namespace PgClient.Tests;

public class BufferStreamReaderTests
{
    [Fact]
    public void ReadMessage_ParsesCodeLengthAndPayload()
    {
        var payload = Encoding.UTF8.GetBytes("hello");
        var frame = FrameMessage((byte)'R', payload);

        using var reader = new BufferStreamReader();
        using var ms = new MemoryStream(frame);
        var (code, totalLength, body) = reader.ReadMessage(ms);

        Assert.Equal((byte)'R', code);
        Assert.Equal(4 + payload.Length, totalLength);
        Assert.Equal(payload, body);
    }

    [Fact]
    public void ReadMessage_ReusesInternalBuffer()
    {
        var m1 = FrameMessage((byte)'A', Encoding.UTF8.GetBytes("first"));
        var m2 = FrameMessage((byte)'B', Encoding.UTF8.GetBytes("second-message-payload"));
        var all = m1.Concat(m2).ToArray();

        using var reader = new BufferStreamReader();
        using var ms = new MemoryStream(all);

        var (c1, _, p1) = reader.ReadMessage(ms);
        var (c2, _, p2) = reader.ReadMessage(ms);

        Assert.Equal((byte)'A', c1);
        Assert.Equal("first", Encoding.UTF8.GetString(p1));
        Assert.Equal((byte)'B', c2);
        Assert.Equal("second-message-payload", Encoding.UTF8.GetString(p2));
    }

    [Fact]
    public async Task ReadQueryMessageAsync_ParsesFrame()
    {
        var payload = Encoding.UTF8.GetBytes("data-row-bytes");
        var frame = FrameMessage((byte)'D', payload);

        using var reader = new BufferStreamReader();
        using var ms = new MemoryStream(frame);
        var (code, body) = await reader.ReadQueryMessageAsync(ms);

        Assert.Equal((byte)'D', code);
        Assert.Equal(payload, body);
    }

    [Fact]
    public void ReadMessage_InvalidLength_Throws()
    {
        var frame = new byte[] { (byte)'X', 0x00, 0x00, 0x00, 0x00 }; // length < 4
        using var reader = new BufferStreamReader();
        using var ms = new MemoryStream(frame);
        Assert.Throws<InvalidDataException>(() => reader.ReadMessage(ms));
    }

    private static byte[] FrameMessage(byte code, byte[] payload)
    {
        var frame = new byte[1 + 4 + payload.Length];
        frame[0] = code;
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(1, 4), 4 + payload.Length);
        payload.CopyTo(frame.AsSpan(5));
        return frame;
    }
}
