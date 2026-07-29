using System.Buffers.Binary;
using System.Text;

namespace PgClient.Utilities;

/// Low-level big-endian binary helpers for the Postgres wire protocol.
public static class Helper
{
    public static void WriteCString(BinaryWriter writer, string value)
    {
        int max = Encoding.UTF8.GetMaxByteCount(value.Length);
        if (max <= 512)
        {
            Span<byte> stack = stackalloc byte[max];
            int written = Encoding.UTF8.GetBytes(value, stack);
            writer.Write(stack.Slice(0, written));
        }
        else
        {
            byte[] rented = System.Buffers.ArrayPool<byte>.Shared.Rent(max);
            try
            {
                int written = Encoding.UTF8.GetBytes(value, rented);
                writer.Write(rented, 0, written);
            }
            finally
            {
                System.Buffers.ArrayPool<byte>.Shared.Return(rented);
            }
        }
        writer.Write((byte)0);
    }

    public static int ReadInt32BE(Stream s)
    {
        Span<byte> buf = stackalloc byte[4];
        s.ReadExactly(buf);
        return BinaryPrimitives.ReadInt32BigEndian(buf);
    }

    public static int ReadInt32BE(BinaryReader r)
    {
        Span<byte> buf = stackalloc byte[4];
        int read = r.Read(buf);
        if (read < 4) throw new EndOfStreamException();
        return BinaryPrimitives.ReadInt32BigEndian(buf);
    }

    public static short ReadInt16BE(BinaryReader r)
    {
        Span<byte> buf = stackalloc byte[2];
        int read = r.Read(buf);
        if (read < 2) throw new EndOfStreamException();
        return BinaryPrimitives.ReadInt16BigEndian(buf);
    }

    public static short ReadInt16BE(Stream s)
    {
        Span<byte> buf = stackalloc byte[2];
        s.ReadExactly(buf);
        return BinaryPrimitives.ReadInt16BigEndian(buf);
    }

    public static string ReadCString(Stream s)
    {
        var sb = new StringBuilder();
        int b;
        while ((b = s.ReadByte()) > 0)
            sb.Append((char)b);
        return sb.ToString();
    }

    public static string ReadCString(BinaryReader r)
    {
        var sb = new StringBuilder();
        byte b;
        while ((b = r.ReadByte()) != 0)
            sb.Append((char)b);
        return sb.ToString();
    }

    /// Byte-swap for callers that want raw bit patterns.
    public static int ToBigEndian(int value)
        => BinaryPrimitives.ReverseEndianness(value);

    public static void WriteInt32BE(BinaryWriter w, int value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buf, value);
        w.Write(buf);
    }

    public static void WriteInt32BE(Stream s, int value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buf, value);
        s.Write(buf);
    }

    public static void WriteInt32BE(Span<byte> dest, int value)
        => BinaryPrimitives.WriteInt32BigEndian(dest, value);

    // Backwards-compatible aliases still used by existing call sites.
    public static int ReadInt32(Stream s) => ReadInt32BE(s);
    public static int ReadInt32(BinaryReader r) => ReadInt32BE(r);
    public static short ReadInt16(Stream s) => ReadInt16BE(s);
    public static short ReadInt16(BinaryReader r) => ReadInt16BE(r);
    public static void WriteInt32(Stream s, int value) => WriteInt32BE(s, value);
    public static void WriteInt32(Span<byte> s, int value) => WriteInt32BE(s, value);
}
