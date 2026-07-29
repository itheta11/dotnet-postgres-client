using PgClient.Query;
using PgClient.Response;
using Xunit;

namespace PgClient.Tests;

public class PgCopyStreamTests
{
    [Fact]
    public void PgCopyInStream_WriteEmitsCopyDataFrames()
    {
        using var ms = new MemoryStream();
        var protocol = new BufferUtils.BufferStreamReader();
        var copy = new PgCopyInStream(ms, protocol, onReadyForQuery: null);

        byte[] payload = { 1, 2, 3, 4, 5 };
        copy.Write(payload, 0, payload.Length);

        var frame = ms.ToArray();
        Assert.Equal((byte)'d', frame[0]);
        int len = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(frame.AsSpan(1, 4));
        Assert.Equal(4 + payload.Length, len);
        Assert.Equal(payload, frame.AsSpan(5, payload.Length).ToArray());
    }

    [Fact]
    public void PgCopyInStream_CancelSendsCopyFail()
    {
        using var ms = new MemoryStream();
        var protocol = new BufferUtils.BufferStreamReader();
        var copy = new PgCopyInStream(ms, protocol, onReadyForQuery: null);

        copy.Cancel("oops");

        var frame = ms.ToArray();
        Assert.Equal((byte)'f', frame[0]);
    }
}
