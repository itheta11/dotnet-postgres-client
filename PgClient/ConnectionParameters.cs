public class ConnectionParameters
{
    public required string Hostname { get; set; }
    public required int Port { get; set; }

    public required string Database { get; set; }

    public required string Username { get; set; }

    public string Password { get; set; }

    public string ApplicationName { get; set; }

    public string FallbackApplicationName { get; set; }
}