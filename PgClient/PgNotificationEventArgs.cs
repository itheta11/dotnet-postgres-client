namespace PgClient;

/// A LISTEN/NOTIFY notification pushed by the server.
public sealed class PgNotificationEventArgs : EventArgs
{
    public int Pid { get; }
    public string Channel { get; }
    public string Payload { get; }

    public PgNotificationEventArgs(int pid, string channel, string payload)
    {
        Pid = pid;
        Channel = channel;
        Payload = payload;
    }
}
