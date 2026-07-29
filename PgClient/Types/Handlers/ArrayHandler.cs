using System.Buffers.Binary;
using System.Text;
using PgClient.Response;

namespace PgClient.Types.Handlers;

/// A text-format array handler for a single element type, e.g. int[] backed by
/// Postgres int4[]. Binary format is out of scope for v1 because it requires a
/// multi-byte header that varies with dimensionality; text format is what the
/// server sends when the caller doesn't opt in to binary results.
///
/// Text format examples:
///   {1,2,3}
///   {"a","b\"c",NULL}
public sealed class ArrayHandler : PgTypeHandler
{
    private readonly uint _arrayOid;
    private readonly PgTypeHandler _element;

    public ArrayHandler(uint arrayOid, PgTypeHandler element)
    {
        _arrayOid = arrayOid;
        _element = element;
    }

    public override uint TypeOid => _arrayOid;
    public override Type ClrType => _element.ClrType.MakeArrayType();

    public override object ReadText(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 2 || bytes[0] != (byte)'{')
            throw new FormatException("Invalid array literal.");

        var list = new List<object?>();
        int i = 1;
        var elementBuf = new List<byte>(32);
        bool inQuotes = false;
        bool isNull = false;
        bool started = false;

        for (; i < bytes.Length; i++)
        {
            byte c = bytes[i];
            if (!inQuotes && c == (byte)'}')
            {
                if (started) FlushElement(list, elementBuf, isNull);
                break;
            }
            if (!inQuotes && c == (byte)',')
            {
                FlushElement(list, elementBuf, isNull);
                elementBuf.Clear();
                isNull = false;
                started = false;
                continue;
            }
            if (c == (byte)'"')
            {
                inQuotes = !inQuotes;
                started = true;
                continue;
            }
            if (c == (byte)'\\' && i + 1 < bytes.Length)
            {
                // Backslash escape (valid both inside and outside quoted elements).
                elementBuf.Add(bytes[++i]);
                started = true;
                continue;
            }
            elementBuf.Add(c);
            started = true;
            if (!inQuotes
                && elementBuf.Count == 4
                && elementBuf[0] == (byte)'N' && elementBuf[1] == (byte)'U'
                && elementBuf[2] == (byte)'L' && elementBuf[3] == (byte)'L')
            {
                isNull = true;
            }
        }

        Array result = Array.CreateInstance(_element.ClrType, list.Count);
        for (int j = 0; j < list.Count; j++)
            result.SetValue(list[j], j);
        return result;
    }

    private void FlushElement(List<object?> list, List<byte> buf, bool isNull)
    {
        if (isNull)
        {
            list.Add(null);
            return;
        }
        Span<byte> span = System.Runtime.InteropServices.CollectionsMarshal.AsSpan(buf);
        list.Add(_element.ReadText(span));
    }

    public override byte[] EncodeText(object value)
    {
        var arr = (Array)value;
        var sb = new StringBuilder();
        sb.Append('{');
        for (int i = 0; i < arr.Length; i++)
        {
            if (i > 0) sb.Append(',');
            object? el = arr.GetValue(i);
            if (el is null)
            {
                sb.Append("NULL");
                continue;
            }
            var elBytes = _element.EncodeText(el);
            string s = Encoding.UTF8.GetString(elBytes);
            if (NeedsQuoting(s))
            {
                sb.Append('"');
                foreach (var ch in s)
                {
                    if (ch == '"' || ch == '\\') sb.Append('\\');
                    sb.Append(ch);
                }
                sb.Append('"');
            }
            else
            {
                sb.Append(s);
            }
        }
        sb.Append('}');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static bool NeedsQuoting(string s)
    {
        if (s.Length == 0) return true;
        if (s.Equals("NULL", StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var ch in s)
        {
            if (ch == '{' || ch == '}' || ch == ',' || ch == '"' || ch == '\\' || char.IsWhiteSpace(ch))
                return true;
        }
        return false;
    }
}
