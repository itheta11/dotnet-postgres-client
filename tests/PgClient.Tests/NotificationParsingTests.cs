using System.Buffers.Binary;
using PgClient;
using PgClient.BufferUtils;
using PgClient.Response;
using Xunit;

namespace PgClient.Tests;

public class NotificationParsingTests
{
    [Fact]
    public void PgDataReader_DispatchesNotificationResponse()
    {
        // NotificationResponse payload: pid (Int32) + channel (CString) + payload (CString)
        int pid = 12345;
        string channel = "chat";
        string message = "hello";

        var payload = new List<byte>();
        Span<byte> pidBuf = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(pidBuf, pid);
        payload.AddRange(pidBuf.ToArray());
        payload.AddRange(System.Text.Encoding.UTF8.GetBytes(channel));
        payload.Add(0);
        payload.AddRange(System.Text.Encoding.UTF8.GetBytes(message));
        payload.Add(0);

        // Build a fake server stream: NotificationResponse + ReadyForQuery
        using var ms = new MemoryStream();
        WriteMessage(ms, (byte)'A', payload.ToArray());
        WriteMessage(ms, (byte)'Z', new byte[] { (byte)'I' });
        ms.Position = 0;

        int gotPid = -1;
        string? gotChannel = null;
        string? gotPayload = null;

        var protocol = new BufferStreamReader();
        var reader = new PgDataReader(
            ms, protocol,
            onNotification: (p, c, m) => { gotPid = p; gotChannel = c; gotPayload = m; });
        _ = reader.ReadAsync().AsTask().GetAwaiter().GetResult();

        Assert.Equal(pid, gotPid);
        Assert.Equal(channel, gotChannel);
        Assert.Equal(message, gotPayload);
    }

    private static void WriteMessage(Stream s, byte code, byte[] payload)
    {
        s.WriteByte(code);
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(len, 4 + payload.Length);
        s.Write(len);
        s.Write(payload);
    }
}
