using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace PgClient;

public class BufferWriter : IDisposable
{
    private byte[] _buffer;
    private int _position;
    private readonly ArrayPool<byte> _pool;
    private bool _disposed;
    public BufferWriter(int IntialCapacity = 256)
    {
        _pool = ArrayPool<byte>.Shared;
        _buffer = _pool.Rent(IntialCapacity);
        _position = 0;
    }

    public int Length => _position;
    public ReadOnlySpan<byte> WrittenSpan => new ReadOnlySpan<byte>(_buffer, 0, _position);

    public byte[] WrittenBytes
    {
        get
        {
            var result = new byte[_position];
            Buffer.BlockCopy(_buffer, 0, result, 0, _position);
            return result;
        }
    }

    public void EnsureCapacity(int additionalBytes)
    {
        int required = _position + additionalBytes;
        if (required <= _buffer.Length) return;

        int newSize = Math.Max(required, _buffer.Length * 2);
        byte[] newBuffer = _pool.Rent(newSize);
        Buffer.BlockCopy(_buffer, 0, newBuffer, 0, _position);

        _pool.Return(_buffer);
        _buffer = newBuffer;

    }

    public void WriteInt16(short value)
    {
        EnsureCapacity(2);
        BinaryPrimitives.WriteInt16BigEndian(_buffer.AsSpan(_position), value);
        _position += 2;
    }

    public void WriteInt32(int value)
    {
        EnsureCapacity(4);
        BinaryPrimitives.WriteInt32BigEndian(_buffer.AsSpan(_position), value);
        _position += 4;
    }

    public void WriteByte(byte value)
    {
        EnsureCapacity(1);
        _buffer[_position++] = value;
    }

    public void WriteBytes(ReadOnlySpan<byte> bytes)
    {
        EnsureCapacity(bytes.Length);
        bytes.CopyTo(_buffer.AsSpan(_position));
        _position += bytes.Length;
    }

    /// <summary>
    /// Writes a standard UTF-8 string prefixed by its byte length (Big Endian).
    /// </summary>
    public void WriteString(string value)
    {
        if (value == null)
        {
            WriteInt32(-1);
            return;
        }

        int byteCount = Encoding.UTF8.GetByteCount(value);
        WriteInt32(byteCount); // Write length prefix (Big Endian)
        EnsureCapacity(byteCount);
        Encoding.UTF8.GetBytes(value, _buffer.AsSpan(_position));
        _position += byteCount;
    }

    /// <summary>
    /// Writes a null-terminated (C-style) UTF-8 string used in Postgres protocol.
    /// </summary>
    public void WriteCString(string value)
    {
        if (value == null)
        {
            // Write only the null terminator
            WriteByte(0);
            return;
        }

        int byteCount = Encoding.UTF8.GetByteCount(value);
        EnsureCapacity(byteCount + 1); // +1 for '\0'
        _position += Encoding.UTF8.GetBytes(value, _buffer.AsSpan(_position));
        _buffer[_position++] = 0; // null terminator
    }


    public void Reset() => _position = 0;

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
                _pool.Return(_buffer);
                _buffer = null!;
            }
            _disposed = true;
        }

    }

    ~BufferWriter()
    {
        Dispose(false);
    }
}