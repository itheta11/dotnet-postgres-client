using System.Buffers;
using System.Buffers.Binary;

namespace PgClient.BufferUtils;

/// Reusable Postgres wire-message reader.
///
/// Owns a single pooled scratch buffer that grows as needed. Meant to be created
/// once per <see cref="System.Net.Sockets.NetworkStream"/> and reused for the
/// entire connection lifetime. Not thread-safe.
public sealed class BufferStreamReader : IAsyncDisposable, IDisposable
{
    private byte[] _payloadBuffer = Array.Empty<byte>();
    private bool _disposed;

    /// Reads a Postgres backend message (1-byte code + 4-byte length + payload).
    /// Payload does NOT include the length prefix. Returned array is a fresh copy
    /// owned by the caller.
    public (byte Code, int TotalLength, byte[] Payload) ReadMessage(Stream stream)
    {
        EnsureNotDisposed();

        Span<byte> header = stackalloc byte[5];
        stream.ReadExactly(header);

        byte code = header[0];
        int length = BinaryPrimitives.ReadInt32BigEndian(header.Slice(1, 4));
        int payloadLength = length - 4;
        if (payloadLength < 0)
            throw new InvalidDataException($"Invalid message length: {length}");

        EnsurePayloadCapacity(payloadLength);
        stream.ReadExactly(_payloadBuffer, 0, payloadLength);

        var result = new byte[payloadLength];
        Buffer.BlockCopy(_payloadBuffer, 0, result, 0, payloadLength);
        return (code, length, result);
    }

    public (byte Code, byte[] Payload) ReadQueryMessage(Stream stream)
    {
        var (code, _, payload) = ReadMessage(stream);
        return (code, payload);
    }

    public async ValueTask<(byte Code, byte[] Payload)> ReadQueryMessageAsync(Stream stream, CancellationToken ct = default)
    {
        EnsureNotDisposed();

        byte[] header = ArrayPool<byte>.Shared.Rent(5);
        int length;
        byte code;
        try
        {
            await stream.ReadExactlyAsync(header.AsMemory(0, 5), ct).ConfigureAwait(false);
            code = header[0];
            length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1, 4));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(header);
        }

        int payloadLength = length - 4;
        if (payloadLength < 0)
            throw new InvalidDataException($"Invalid message length: {length}");

        EnsurePayloadCapacity(payloadLength);
        await stream.ReadExactlyAsync(_payloadBuffer.AsMemory(0, payloadLength), ct).ConfigureAwait(false);

        var result = new byte[payloadLength];
        Buffer.BlockCopy(_payloadBuffer, 0, result, 0, payloadLength);
        return (code, result);
    }

    private void EnsurePayloadCapacity(int payloadLength)
    {
        if (_payloadBuffer.Length >= payloadLength) return;

        if (_payloadBuffer.Length > 0)
            ArrayPool<byte>.Shared.Return(_payloadBuffer, clearArray: false);

        _payloadBuffer = ArrayPool<byte>.Shared.Rent(payloadLength);
    }

    private void EnsureNotDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(BufferStreamReader));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_payloadBuffer.Length > 0)
        {
            ArrayPool<byte>.Shared.Return(_payloadBuffer, clearArray: false);
            _payloadBuffer = Array.Empty<byte>();
        }
        GC.SuppressFinalize(this);
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }
}
