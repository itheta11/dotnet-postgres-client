using System.Text;

namespace PgClient.Response;

/// Structured Postgres ErrorResponse / NoticeResponse fields (RFC-style codes).
public sealed class PgErrorInfo
{
    public string? Severity { get; init; }
    public string? SeverityNonLocalized { get; init; }
    public string? SqlState { get; init; }
    public string? Message { get; init; }
    public string? Detail { get; init; }
    public string? Hint { get; init; }
    public string? Position { get; init; }
    public string? InternalPosition { get; init; }
    public string? InternalQuery { get; init; }
    public string? Where { get; init; }
    public string? SchemaName { get; init; }
    public string? TableName { get; init; }
    public string? ColumnName { get; init; }
    public string? DataTypeName { get; init; }
    public string? ConstraintName { get; init; }
    public string? File { get; init; }
    public string? Line { get; init; }
    public string? Routine { get; init; }

    /// Parses the payload of an ErrorResponse (E) or NoticeResponse (N) message.
    /// Payload layout: sequence of (byte field-code + CString value) terminated by 0.
    public static PgErrorInfo Parse(ReadOnlySpan<byte> payload)
    {
        string? severity = null, severityNL = null, sqlState = null, message = null;
        string? detail = null, hint = null, position = null, internalPos = null;
        string? internalQuery = null, where = null, schema = null, table = null;
        string? column = null, dataType = null, constraint = null, file = null;
        string? line = null, routine = null;

        int i = 0;
        while (i < payload.Length)
        {
            byte code = payload[i++];
            if (code == 0) break;

            int start = i;
            while (i < payload.Length && payload[i] != 0) i++;
            if (i >= payload.Length)
                throw new InvalidDataException("Unterminated CString in ErrorResponse payload.");

            string value = Encoding.UTF8.GetString(payload.Slice(start, i - start));
            i++; // skip null terminator

            switch ((char)code)
            {
                case 'S': severity = value; break;
                case 'V': severityNL = value; break;
                case 'C': sqlState = value; break;
                case 'M': message = value; break;
                case 'D': detail = value; break;
                case 'H': hint = value; break;
                case 'P': position = value; break;
                case 'p': internalPos = value; break;
                case 'q': internalQuery = value; break;
                case 'W': where = value; break;
                case 's': schema = value; break;
                case 't': table = value; break;
                case 'c': column = value; break;
                case 'd': dataType = value; break;
                case 'n': constraint = value; break;
                case 'F': file = value; break;
                case 'L': line = value; break;
                case 'R': routine = value; break;
            }
        }

        return new PgErrorInfo
        {
            Severity = severity,
            SeverityNonLocalized = severityNL,
            SqlState = sqlState,
            Message = message,
            Detail = detail,
            Hint = hint,
            Position = position,
            InternalPosition = internalPos,
            InternalQuery = internalQuery,
            Where = where,
            SchemaName = schema,
            TableName = table,
            ColumnName = column,
            DataTypeName = dataType,
            ConstraintName = constraint,
            File = file,
            Line = line,
            Routine = routine,
        };
    }

    public override string ToString()
        => $"{Severity ?? "ERROR"} {SqlState}: {Message}";
}
