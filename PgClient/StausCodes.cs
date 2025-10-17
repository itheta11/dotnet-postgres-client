namespace PgClient;

public enum StatusCodes
{
    StartUp = 0x70,
    Query = 0x51,
    Parse = 0x50,
    Bind = 0x42,
    Execute = 0x45,
    Flush = 0x48,
    Sync = 0x53,
    End = 0x58,
    Close = 0x43,
    Describe = 0x44,
    CopyFromChunk = 0x64,
    CopyDone = 0x63,
    CopyFail = 0x66,
}