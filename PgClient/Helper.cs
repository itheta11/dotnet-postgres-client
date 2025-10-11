using System;
using System.Net.Sockets;

namespace PgClient;

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

    public static int ToBigEndian(int value)
        => ((value & 0xFF) << 24) | ((value & 0xFF00) << 8)
         | ((value >> 8) & 0xFF00) | ((value >> 24) & 0xFF);
}
