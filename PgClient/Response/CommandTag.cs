using System.Globalization;
using System.Text;

namespace PgClient.Response;

/// Parsed representation of a CommandComplete tag such as
/// "SELECT 10", "INSERT 0 5", "UPDATE 3", "DELETE 2", "COPY 100".
public readonly struct CommandTag
{
    public string Operation { get; }
    public uint InsertOid { get; }
    public long RowsAffected { get; }

    public CommandTag(string operation, uint insertOid, long rowsAffected)
    {
        Operation = operation;
        InsertOid = insertOid;
        RowsAffected = rowsAffected;
    }

    public static CommandTag Empty { get; } = new CommandTag(string.Empty, 0, -1);

    /// Payload is a null-terminated ASCII string.
    public static CommandTag Parse(ReadOnlySpan<byte> payload)
    {
        int end = payload.IndexOf((byte)0);
        if (end < 0) end = payload.Length;
        if (end == 0) return Empty;

        string tag = Encoding.ASCII.GetString(payload.Slice(0, end));
        return ParseTag(tag);
    }

    internal static CommandTag ParseTagInternal(string tag) => ParseTag(tag);

    public static CommandTag ParseTag(string tag)
    {
        // Split into space-separated tokens.
        var parts = tag.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return Empty;

        string op = parts[0];

        if (op == "INSERT" && parts.Length >= 3)
        {
            uint oid = uint.Parse(parts[1], CultureInfo.InvariantCulture);
            long rows = long.Parse(parts[2], CultureInfo.InvariantCulture);
            return new CommandTag(op, oid, rows);
        }

        if (parts.Length >= 2 &&
            long.TryParse(parts[^1], NumberStyles.Integer, CultureInfo.InvariantCulture, out long affected))
        {
            return new CommandTag(op, 0, affected);
        }

        return new CommandTag(op, 0, -1);
    }
}
