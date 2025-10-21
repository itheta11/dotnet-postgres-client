using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;

namespace PgClient.BufferUtils;

public class BufferReader : IDisposable
{
    public byte[] _buffer;
    private int _offset;

    public int Remaining => _buffer.Length - _offset;
    public int Position => _offset;
    public int Length => _buffer.Length;
    private bool _disposed;

    public BufferReader()
    {
    }

    /// <summary>
    /// Assigns the byte buffer to read from.
    /// </summary>
    public void SetBuffer(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer.ToArray();
        _offset = 0;
    }

    private void Ensure(int count)
    {
        if (_offset + count > _buffer.Length)
            throw new InvalidOperationException("Not enough data in buffer.");
    }

    public byte ReadByte()
    {
        Ensure(1);
        return _buffer[_offset++];
    }

    public short ReadInt16()
    {
        Ensure(2);
        short value = BinaryPrimitives.ReadInt16BigEndian(_buffer.AsSpan().Slice(_offset, 2));
        _offset += 2;
        return value;
    }

    public int ReadInt32()
    {
        Ensure(4);
        int value = BinaryPrimitives.ReadInt32BigEndian(_buffer.AsSpan().Slice(_offset, 4));
        _offset += 4;
        return value;
    }

    public uint ReadUInt32()
    {
        Ensure(4);
        uint value = BinaryPrimitives.ReadUInt32BigEndian(_buffer.AsSpan().Slice(_offset, 4));
        _offset += 4;
        return value;
    }

    /// <summary>
    /// Reads a null-terminated UTF-8 string (C-style, used heavily in Postgres).
    /// </summary>
    public string ReadCString()
    {
        int start = _offset;
        while (_offset < _buffer.Length && _buffer[_offset] != 0)
            _offset++;

        if (_offset >= _buffer.Length)
            throw new InvalidOperationException("CString not null-terminated.");

        string value = Encoding.UTF8.GetString(_buffer.AsSpan().Slice(start, _offset - start));
        _offset++; // Skip the null terminator
        return value;
    }

    /// <summary>
    /// Reads a UTF-8 string prefixed by a 4-byte Big Endian length.
    /// Returns null if the length is -1.
    /// </summary>
    public string? ReadString()
    {
        int length = ReadInt32(); // Big Endian length prefix
        if (length == -1)
            return null;

        if (length < 0)
            throw new InvalidOperationException($"Invalid string length: {length}");

        Ensure(length);
        string value = Encoding.UTF8.GetString(_buffer.AsSpan().Slice(_offset, length));
        _offset += length;
        return value;
    }

    // ---------- Raw Data Readers ----------

    /// <summary>
    /// Reads raw bytes of the specified length.
    /// </summary>
    public ReadOnlySpan<byte> ReadBytes(int length)
    {
        Ensure(length);
        var span = _buffer.AsSpan();
        _offset += length;
        return span;
    }

    /// <summary>
    /// Skips a given number of bytes.
    /// </summary>
    public void Skip(int count)
    {
        Ensure(count);
        _offset += count;
    }


    public byte[] ReadAllBytesFromStream(NetworkStream stream)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));

        using (var memoryStream = new MemoryStream())
        {
            byte[] buffer = new byte[8192]; // 8 KB buffer
            int bytesRead;

            // Keep reading until no more data
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                memoryStream.Write(buffer, 0, bytesRead);

                // Optional: break if stream indicates end of message
                // e.g. if (stream.DataAvailable == false) break;
            }

            return memoryStream.ToArray();
        }
    }

    /// <summary>
    /// Resets reading position to start.
    /// </summary>
    public void Reset() => _offset = 0;

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _buffer = null!;
                _offset = 0;
            }
            _disposed = true;
        }

    }

    ~BufferReader()
    {
        Dispose(false);
    }

}