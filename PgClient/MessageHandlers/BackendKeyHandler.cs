using System;
using PgClient.Utilities;

namespace PgClient.MessageHandlers;

public class BackendKeyHandler
{
    public (int ProcessId, int SecretKey) HandleBankendKey(byte[] payload)
    {
        using var ms = new MemoryStream(payload);
        using var reader = new BinaryReader(ms);

        int Pid = Helper.ReadInt32(reader);
        int SecretKey = Helper.ReadInt32(reader);

        return (Pid, SecretKey);
    }
}
