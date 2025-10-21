using System;
using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;

namespace PgClient.Utilities;

public static class Helper
{
    public static void WriteCString(BinaryWriter writer, string value)
    {
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(value);
        writer.Write(bytes);
        writer.Write((byte)0);
    }

    public static void SkipMessage(NetworkStream stream, int length)
    {
        byte[] buf = new byte[length];
        stream.Read(buf, 0, length);
    }

    public static int ReadInt32(Stream s)
    {
        byte[] buf = new byte[4];
        s.Read(buf, 0, 4);
        return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    }

    public static int ReadInt32(BinaryReader r)
    {
        var b = r.ReadBytes(4);
        if (BitConverter.IsLittleEndian) Array.Reverse(b);
        return BitConverter.ToInt32(b, 0);
    }

    public static short ReadInt16(BinaryReader r)
    {
        var b = r.ReadBytes(2);
        if (BitConverter.IsLittleEndian) Array.Reverse(b);
        return BitConverter.ToInt16(b, 0);
    }

    public static short ReadInt16(Stream s)
    {
        byte[] buf = new byte[2];
        s.Read(buf, 0, 2);
        return (short)((buf[0] << 8) | buf[1]);
    }

    public static string ReadCString(Stream s)
    {
        var sb = new System.Text.StringBuilder();
        int b;
        while ((b = s.ReadByte()) > 0)
            sb.Append((char)b);
        return sb.ToString();
    }

    public static string ReadCString(BinaryReader r)
    {
        var bytes = new List<byte>();
        byte b;
        while ((b = r.ReadByte()) != 0)
            bytes.Add(b);
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    public static int ToBigEndian(int value)
        => ((value & 0xFF) << 24) | ((value & 0xFF00) << 8)
         | ((value >> 8) & 0xFF00) | ((value >> 24) & 0xFF);

    public static void WriteInt32BE(BinaryWriter w, int value)
    {
        Span<byte> span = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(span, value);
        w.Write(span.ToArray());
    }

    public static void WriteInt32(Stream s, int value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        s.Write(bytes, 0, 4);
    }

    public static void WriteInt32(Span<byte> s, int value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        bytes.CopyTo(s);
    }
}
