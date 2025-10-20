namespace PgClient;
public enum PgConnectionState
{
    Disconnected,
    Connecting,
    Authenticating,
    Ready,
    Closing,
    Closed,
    Faulted
}