using System.Buffers;
using System.Text;

namespace PgClient.BufferUtils;

public class BufferStreamReader : IAsyncDisposable, IDisposable
{
    private readonly byte[] _headerBuffer = new byte[5]; // 1 for code + 4 for length
    private byte[] _payloadBuffer = Array.Empty<byte>();
    private bool _disposed;

    public BufferStreamReader()
    {
    }

    /// <summary>
    /// Reads the next Postgres message (code + payload) asynchronously.
    /// </summary>
    public (byte Code, int totalLength, byte[] Payload) ReadMessage(Stream stream)
    {
        EnsureNotDisposed();

        // Read header (1 byte for code, 4 bytes for length)
        ReadExact(stream,_headerBuffer, 0, 5);

        byte code = _headerBuffer[0];
        int length = ReadInt32(_headerBuffer, 1); // total length includes itself

        // Subtract 4 since length includes the length field itself
        int payloadLength = length - 4;

        if (payloadLength < 0)
            throw new InvalidDataException($"Invalid message length: {length}");

        // Rent or reuse payload buffer
        if (_payloadBuffer.Length < payloadLength)
            _payloadBuffer = ArrayPool<byte>.Shared.Rent(payloadLength);

        ReadExact(stream, _payloadBuffer, 0, payloadLength);

        // Copy into exact-sized array before returning
        var result = new byte[payloadLength];
        Buffer.BlockCopy(_payloadBuffer, 0, result, 0, payloadLength);
        var c = Encoding.UTF8.GetString(result);
        return (code, length, result);
    }

    private static int ReadInt32(byte[] buffer, int offset)
    {
        // Postgres uses big-endian order
        return (buffer[offset] << 24) |
               (buffer[offset + 1] << 16) |
               (buffer[offset + 2] << 8) |
               buffer[offset + 3];
    }

    private void ReadExact(Stream stream,byte[] buffer, int offset, int count)
    {
        int readTotal = 0;
        while (readTotal < count)
        {
            int read = stream.Read(buffer, offset + readTotal, count - readTotal);
            if (read == 0)
                throw new EndOfStreamException("Stream ended before all bytes could be read.");
            readTotal += read;
        }
    }

    private void EnsureNotDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(BufferStreamReader));
    }

    public void Dispose()
    {
        DisposeAsync().AsTask().GetAwaiter().GetResult();
        GC.SuppressFinalize(this);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;

        _disposed = true;
        ArrayPool<byte>.Shared.Return(_payloadBuffer, clearArray: true);
    }
}