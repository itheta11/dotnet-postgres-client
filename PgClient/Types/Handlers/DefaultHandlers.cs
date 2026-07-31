using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using PgClient.Response;

namespace PgClient.Types.Handlers;

public sealed class BoolHandler : PgTypeHandler
{
    public override uint TypeOid => PgOid.Bool;
    public override Type ClrType => typeof(bool);
    public override bool SupportsBinary => true;

    public override object ReadText(ReadOnlySpan<byte> bytes)
        => bytes.Length == 1 && (bytes[0] == (byte)'t' || bytes[0] == (byte)'1');

    public override object ReadBinary(ReadOnlySpan<byte> bytes)
        => bytes.Length >= 1 && bytes[0] != 0;

    public override byte[] EncodeText(object value)
        => new[] { (bool)value ? (byte)'t' : (byte)'f' };

    public override byte[] EncodeBinary(object value)
        => new[] { (bool)value ? (byte)1 : (byte)0 };
}

public sealed class Int2Handler : PgTypeHandler
{
    public override uint TypeOid => PgOid.Int2;
    public override Type ClrType => typeof(short);
    public override bool SupportsBinary => true;

    public override object ReadText(ReadOnlySpan<byte> bytes)
        => short.Parse(Encoding.ASCII.GetString(bytes), CultureInfo.InvariantCulture);

    public override object ReadBinary(ReadOnlySpan<byte> bytes)
        => BinaryPrimitives.ReadInt16BigEndian(bytes);

    public override byte[] EncodeText(object value)
        => Encoding.ASCII.GetBytes(((short)value).ToString(CultureInfo.InvariantCulture));

    public override byte[] EncodeBinary(object value)
    {
        var buf = new byte[2];
        BinaryPrimitives.WriteInt16BigEndian(buf, (short)value);
        return buf;
    }
}

public sealed class Int4Handler : PgTypeHandler
{
    public override uint TypeOid => PgOid.Int4;
    public override Type ClrType => typeof(int);
    public override bool SupportsBinary => true;

    public override object ReadText(ReadOnlySpan<byte> bytes)
        => int.Parse(Encoding.ASCII.GetString(bytes), CultureInfo.InvariantCulture);

    public override object ReadBinary(ReadOnlySpan<byte> bytes)
        => BinaryPrimitives.ReadInt32BigEndian(bytes);

    public override byte[] EncodeText(object value)
        => Encoding.ASCII.GetBytes(((int)value).ToString(CultureInfo.InvariantCulture));

    public override byte[] EncodeBinary(object value)
    {
        var buf = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buf, (int)value);
        return buf;
    }
}

public sealed class Int8Handler : PgTypeHandler
{
    public override uint TypeOid => PgOid.Int8;
    public override Type ClrType => typeof(long);
    public override bool SupportsBinary => true;

    public override object ReadText(ReadOnlySpan<byte> bytes)
        => long.Parse(Encoding.ASCII.GetString(bytes), CultureInfo.InvariantCulture);

    public override object ReadBinary(ReadOnlySpan<byte> bytes)
        => BinaryPrimitives.ReadInt64BigEndian(bytes);

    public override byte[] EncodeText(object value)
        => Encoding.ASCII.GetBytes(((long)value).ToString(CultureInfo.InvariantCulture));

    public override byte[] EncodeBinary(object value)
    {
        var buf = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(buf, (long)value);
        return buf;
    }
}

public sealed class Float4Handler : PgTypeHandler
{
    public override uint TypeOid => PgOid.Float4;
    public override Type ClrType => typeof(float);
    public override bool SupportsBinary => true;

    public override object ReadText(ReadOnlySpan<byte> bytes)
        => float.Parse(Encoding.ASCII.GetString(bytes), CultureInfo.InvariantCulture);

    public override object ReadBinary(ReadOnlySpan<byte> bytes)
    {
        int bits = BinaryPrimitives.ReadInt32BigEndian(bytes);
        return BitConverter.Int32BitsToSingle(bits);
    }

    public override byte[] EncodeText(object value)
        => Encoding.ASCII.GetBytes(((float)value).ToString("R", CultureInfo.InvariantCulture));

    public override byte[] EncodeBinary(object value)
    {
        var buf = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buf, BitConverter.SingleToInt32Bits((float)value));
        return buf;
    }
}

public sealed class Float8Handler : PgTypeHandler
{
    public override uint TypeOid => PgOid.Float8;
    public override Type ClrType => typeof(double);
    public override bool SupportsBinary => true;

    public override object ReadText(ReadOnlySpan<byte> bytes)
        => double.Parse(Encoding.ASCII.GetString(bytes), CultureInfo.InvariantCulture);

    public override object ReadBinary(ReadOnlySpan<byte> bytes)
    {
        long bits = BinaryPrimitives.ReadInt64BigEndian(bytes);
        return BitConverter.Int64BitsToDouble(bits);
    }

    public override byte[] EncodeText(object value)
        => Encoding.ASCII.GetBytes(((double)value).ToString("R", CultureInfo.InvariantCulture));

    public override byte[] EncodeBinary(object value)
    {
        var buf = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(buf, BitConverter.DoubleToInt64Bits((double)value));
        return buf;
    }
}

public sealed class NumericHandler : PgTypeHandler
{
    public override uint TypeOid => PgOid.Numeric;
    public override Type ClrType => typeof(decimal);

    public override object ReadText(ReadOnlySpan<byte> bytes)
        => decimal.Parse(Encoding.ASCII.GetString(bytes), NumberStyles.Number, CultureInfo.InvariantCulture);

    public override byte[] EncodeText(object value)
        => Encoding.ASCII.GetBytes(((decimal)value).ToString(CultureInfo.InvariantCulture));
}

public sealed class TextHandler : PgTypeHandler
{
    private readonly uint _oid;
    public TextHandler(uint oid) { _oid = oid; }

    public override uint TypeOid => _oid;
    public override Type ClrType => typeof(string);
    public override bool SupportsBinary => true;

    public override object ReadText(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(bytes);
    public override object ReadBinary(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(bytes);
    public override byte[] EncodeText(object value) => Encoding.UTF8.GetBytes((string)value);
    public override byte[] EncodeBinary(object value) => Encoding.UTF8.GetBytes((string)value);
}

public sealed class UuidHandler : PgTypeHandler
{
    public override uint TypeOid => PgOid.Uuid;
    public override Type ClrType => typeof(Guid);
    public override bool SupportsBinary => true;

    public override object ReadText(ReadOnlySpan<byte> bytes)
        => Guid.Parse(Encoding.ASCII.GetString(bytes));

    public override object ReadBinary(ReadOnlySpan<byte> bytes)
    {
        Span<byte> tmp = stackalloc byte[16];
        bytes.Slice(0, 16).CopyTo(tmp);
        // Postgres UUID binary is big-endian; Guid ctor expects little-endian first 3 fields.
        (tmp[0], tmp[3]) = (tmp[3], tmp[0]);
        (tmp[1], tmp[2]) = (tmp[2], tmp[1]);
        (tmp[4], tmp[5]) = (tmp[5], tmp[4]);
        (tmp[6], tmp[7]) = (tmp[7], tmp[6]);
        return new Guid(tmp);
    }

    public override byte[] EncodeText(object value)
        => Encoding.ASCII.GetBytes(((Guid)value).ToString("D"));

    public override byte[] EncodeBinary(object value)
    {
        var g = (Guid)value;
        Span<byte> tmp = stackalloc byte[16];
        g.TryWriteBytes(tmp);
        (tmp[0], tmp[3]) = (tmp[3], tmp[0]);
        (tmp[1], tmp[2]) = (tmp[2], tmp[1]);
        (tmp[4], tmp[5]) = (tmp[5], tmp[4]);
        (tmp[6], tmp[7]) = (tmp[7], tmp[6]);
        return tmp.ToArray();
    }
}

public sealed class ByteaHandler : PgTypeHandler
{
    public override uint TypeOid => PgOid.Bytea;
    public override Type ClrType => typeof(byte[]);
    public override bool SupportsBinary => true;

    public override object ReadText(ReadOnlySpan<byte> bytes)
    {
        // Postgres bytea text format is "\x<hex>" (since 9.0) or the older escape format.
        if (bytes.Length >= 2 && bytes[0] == (byte)'\\' && bytes[1] == (byte)'x')
        {
            return Convert.FromHexString(Encoding.ASCII.GetString(bytes.Slice(2)));
        }
        return DecodeEscape(bytes);
    }

    public override object ReadBinary(ReadOnlySpan<byte> bytes) => bytes.ToArray();

    public override byte[] EncodeText(object value)
    {
        var raw = (byte[])value;
#if NET9_0_OR_GREATER
        return Encoding.ASCII.GetBytes("\\x" + Convert.ToHexStringLower(raw));
#else
        return Encoding.ASCII.GetBytes("\\x" + PgClient.Utilities.HexPolyfill.ToHexStringLower(raw));
#endif
    }

    public override byte[] EncodeBinary(object value) => (byte[])value;

    private static byte[] DecodeEscape(ReadOnlySpan<byte> src)
    {
        var ms = new MemoryStream(src.Length);
        for (int i = 0; i < src.Length; i++)
        {
            byte b = src[i];
            if (b == (byte)'\\' && i + 1 < src.Length && src[i + 1] == (byte)'\\')
            {
                ms.WriteByte((byte)'\\'); i++;
            }
            else if (b == (byte)'\\' && i + 3 < src.Length)
            {
                int v = (src[i + 1] - '0') * 64 + (src[i + 2] - '0') * 8 + (src[i + 3] - '0');
                ms.WriteByte((byte)v); i += 3;
            }
            else
            {
                ms.WriteByte(b);
            }
        }
        return ms.ToArray();
    }
}

public sealed class TimestampHandler : PgTypeHandler
{
    private readonly uint _oid;
    public TimestampHandler(uint oid) { _oid = oid; }

    public override uint TypeOid => _oid;
    public override Type ClrType => typeof(DateTime);

    public override object ReadText(ReadOnlySpan<byte> bytes)
    {
        string s = Encoding.ASCII.GetString(bytes);
        // Text format from server is "YYYY-MM-DD HH:MM:SS[.fff][+ZZ]" with DateStyle=ISO,YMD.
        return DateTime.Parse(s, CultureInfo.InvariantCulture,
            _oid == PgOid.TimestampTz
                ? DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal
                : DateTimeStyles.AssumeLocal);
    }

    public override byte[] EncodeText(object value)
    {
        DateTime dt = (DateTime)value;
        string s = dt.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
        return Encoding.ASCII.GetBytes(s);
    }
}

public sealed class DateHandler : PgTypeHandler
{
    public override uint TypeOid => PgOid.Date;
    public override Type ClrType => typeof(DateOnly);

    public override object ReadText(ReadOnlySpan<byte> bytes)
        => DateOnly.Parse(Encoding.ASCII.GetString(bytes), CultureInfo.InvariantCulture);

    public override byte[] EncodeText(object value)
    {
        var d = (DateOnly)value;
        return Encoding.ASCII.GetBytes(d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
    }
}

public sealed class JsonHandler : PgTypeHandler
{
    private readonly uint _oid;
    public JsonHandler(uint oid) { _oid = oid; }

    public override uint TypeOid => _oid;
    public override Type ClrType => typeof(string);

    public override object ReadText(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(bytes);
    public override byte[] EncodeText(object value) => Encoding.UTF8.GetBytes((string)value);
}
