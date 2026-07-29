using System.Buffers.Binary;
using System.Net.Sockets;
using PgClient.Utilities;

namespace PgClient;

/// Sends a Postgres CancelRequest (code 80877102) on a fresh TCP connection.
/// This is the only mechanism that actually interrupts a long-running query
/// server-side.
internal static class PgCancelRequest
{
    private const int CancelRequestCode = 80877102;

    public static async Task SendAsync(
        string host, int port, int processId, int secretKey,
        CancellationToken cancellationToken = default)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
        using var stream = client.GetStream();

        Span<byte> frame = stackalloc byte[16];
        BinaryPrimitives.WriteInt32BigEndian(frame.Slice(0, 4), 16);
        BinaryPrimitives.WriteInt32BigEndian(frame.Slice(4, 4), CancelRequestCode);
        BinaryPrimitives.WriteInt32BigEndian(frame.Slice(8, 4), processId);
        BinaryPrimitives.WriteInt32BigEndian(frame.Slice(12, 4), secretKey);

        await stream.WriteAsync(frame.ToArray(), cancellationToken).ConfigureAwait(false);
        // Server closes the socket after processing — no response.
    }
}
