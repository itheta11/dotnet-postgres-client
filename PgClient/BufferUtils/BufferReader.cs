using System.Buffers.Binary;
using System.Text;

namespace PgClient.BufferUtils;

/// Zero-copy reader over a Postgres message payload.
/// Internally aliases a caller-owned buffer; does not allocate on construction.
public sealed class BufferReader
{
    private ReadOnlyMemory<byte> _buffer;
    private int _offset;

    public int Remaining => _buffer.Length - _offset;
    public int Position => _offset;
    public int Length => _buffer.Length;

    public void SetBuffer(ReadOnlyMemory<byte> buffer)
    {
        _buffer = buffer;
        _offset = 0;
    }

    public void SetBuffer(byte[] buffer)
    {
        _buffer = buffer;
        _offset = 0;
    }

    public void SetBufferCopy(ReadOnlySpan<byte> buffer)
    {
        var copy = new byte[buffer.Length];
        buffer.CopyTo(copy);
        _buffer = copy;
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
        return _buffer.Span[_offset++];
    }

    public short ReadInt16()
    {
        Ensure(2);
        short value = BinaryPrimitives.ReadInt16BigEndian(_buffer.Span.Slice(_offset, 2));
        _offset += 2;
        return value;
    }

    public int ReadInt32()
    {
        Ensure(4);
        int value = BinaryPrimitives.ReadInt32BigEndian(_buffer.Span.Slice(_offset, 4));
        _offset += 4;
        return value;
    }

    public uint ReadUInt32()
    {
        Ensure(4);
        uint value = BinaryPrimitives.ReadUInt32BigEndian(_buffer.Span.Slice(_offset, 4));
        _offset += 4;
        return value;
    }

    /// Reads a null-terminated UTF-8 string.
    public string ReadCString()
    {
        var span = _buffer.Span;
        int start = _offset;
        while (_offset < span.Length && span[_offset] != 0)
            _offset++;

        if (_offset >= span.Length)
            throw new InvalidOperationException("CString not null-terminated.");

        string value = Encoding.UTF8.GetString(span.Slice(start, _offset - start));
        _offset++; // skip terminator
        return value;
    }

    /// Reads a UTF-8 string prefixed with a 4-byte big-endian length. -1 → null.
    public string? ReadString()
    {
        int length = ReadInt32();
        if (length == -1) return null;
        if (length < 0) throw new InvalidOperationException($"Invalid string length: {length}");

        Ensure(length);
        string value = Encoding.UTF8.GetString(_buffer.Span.Slice(_offset, length));
        _offset += length;
        return value;
    }

    /// Returns a slice of the internal buffer without copying.
    public ReadOnlySpan<byte> ReadBytes(int length)
    {
        Ensure(length);
        var slice = _buffer.Span.Slice(_offset, length);
        _offset += length;
        return slice;
    }

    public void Skip(int count)
    {
        Ensure(count);
        _offset += count;
    }

    public void Reset() => _offset = 0;
}
