using System.Collections.Concurrent;
using PgClient.Response;
using PgClient.Types.Handlers;

namespace PgClient.Types;

/// Thread-safe registry of type handlers keyed by Postgres type OID.
/// A single shared default instance is populated with the built-in handlers.
public sealed class PgTypeRegistry
{
    private readonly ConcurrentDictionary<uint, PgTypeHandler> _byOid = new();
    private readonly ConcurrentDictionary<Type, PgTypeHandler> _byClrType = new();

    public static PgTypeRegistry Default { get; } = CreateDefault();

    public void Register(PgTypeHandler handler)
    {
        _byOid[handler.TypeOid] = handler;
        _byClrType[handler.ClrType] = handler;
    }

    public bool TryGet(uint oid, out PgTypeHandler handler)
        => _byOid.TryGetValue(oid, out handler!);

    public bool TryGetForClrType(Type clrType, out PgTypeHandler handler)
        => _byClrType.TryGetValue(clrType, out handler!);

    public PgTypeHandler? Get(uint oid)
        => _byOid.TryGetValue(oid, out var h) ? h : null;

    public PgTypeHandler? GetForClrType(Type clrType)
        => _byClrType.TryGetValue(clrType, out var h) ? h : null;

    private static PgTypeRegistry CreateDefault()
    {
        var r = new PgTypeRegistry();
        r.Register(new BoolHandler());
        r.Register(new Int2Handler());
        r.Register(new Int4Handler());
        r.Register(new Int8Handler());
        r.Register(new Float4Handler());
        r.Register(new Float8Handler());
        r.Register(new NumericHandler());
        r.Register(new TextHandler(PgOid.Text));
        r.Register(new TextHandler(PgOid.Varchar));
        r.Register(new TextHandler(PgOid.Bpchar));
        r.Register(new TextHandler(PgOid.Name));
        r.Register(new TextHandler(PgOid.Unknown));
        r.Register(new UuidHandler());
        r.Register(new ByteaHandler());
        r.Register(new TimestampHandler(PgOid.Timestamp));
        r.Register(new TimestampHandler(PgOid.TimestampTz));
        r.Register(new DateHandler());
        r.Register(new JsonHandler(PgOid.Json));
        r.Register(new JsonHandler(PgOid.Jsonb));
        return r;
    }
}
