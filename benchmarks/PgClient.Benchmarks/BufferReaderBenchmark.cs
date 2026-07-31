using System.Buffers.Binary;
using System.Text;
using BenchmarkDotNet.Attributes;
using PgClient.BufferUtils;

namespace PgClientBenchmarks;

/// Micro-benchmark for the primitive parsing surface used inside every row
/// decode. Does not require a live database.
[MemoryDiagnoser]
public class BufferReaderBenchmark
{
    private byte[] _buffer = Array.Empty<byte>();
    private readonly BufferReader _reader = new();

    [Params(16, 256, 4096)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        // Layout: int32 length + int32 value + string + int16 + int32 (repeated to fill).
        var ms = new MemoryStream();
        var name = Encoding.UTF8.GetBytes("column_name");
        while (ms.Length < PayloadSize)
        {
            Span<byte> tmp = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(tmp, 12345);
            ms.Write(tmp);
            ms.Write(name);
            ms.WriteByte(0);
            BinaryPrimitives.WriteInt16BigEndian(tmp[..2], 7);
            ms.Write(tmp[..2]);
        }
        _buffer = ms.ToArray();
    }

    [Benchmark]
    public int SweepBuffer()
    {
        _reader.SetBuffer(_buffer);
        int total = 0;
        while (_reader.Position < _buffer.Length - 8)
        {
            total += _reader.ReadInt32();
            _ = _reader.ReadCString();
            total += _reader.ReadInt16();
        }
        return total;
    }
}
