using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace PgClient.Crypto;

public class Crypto
{
    private static string[] _mechanisms = { "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256" };
    public static void StartSession(string[] mechanisms, NetworkStream stream)
    {
        var alllMechanism = _mechanisms.Where(x => mechanisms.Contains(x)).ToList();
        if (alllMechanism.Count == 0)
        {
            throw new Exception($"SASL: Only mechanism(s) {string.Join(" and ", _mechanisms)} are allowed");
        }

        
    }
}