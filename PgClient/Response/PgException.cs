namespace PgClient.Response;

public sealed class PgException : Exception
{
    public PgErrorInfo ErrorInfo { get; }
    public string? SqlState => ErrorInfo.SqlState;
    public string? Severity => ErrorInfo.Severity;

    public PgException(PgErrorInfo info)
        : base(info.Message ?? "Postgres error")
    {
        ErrorInfo = info;
    }

    public static PgException FromErrorResponse(ReadOnlySpan<byte> payload)
        => new PgException(PgErrorInfo.Parse(payload));
}
