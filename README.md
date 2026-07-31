# PgClient

A lightweight, allocation-conscious PostgreSQL client for .NET written from
scratch on the raw wire protocol. Zero third-party runtime dependencies.

**Status:** preview. API is stabilising; expect small breaking changes before
`1.0`.

## Features

- Talks Postgres wire protocol v3 directly — no Npgsql, no libpq.
- Simple and extended query protocols.
- Auto-preparation of frequently executed statements.
- Built-in connection pool with prewarm, idle pruning, and max lifetime.
- SCRAM-SHA-256 and MD5 authentication.
- TLS negotiation (`Disable` / `Prefer` / `Require` / `VerifyCa` / `VerifyFull`).
- LISTEN/NOTIFY and query cancellation on a side channel.
- `COPY IN` / `COPY OUT` streaming.
- ADO.NET wrappers (`PgDbConnection`, `PgDbCommand`, `PgDbDataReader`).
- `ILogger` and `System.Diagnostics.Metrics` integration.

## Install

```bash
dotnet add package PgClient
```

Targets `net8.0` and `net9.0`.

## Quick start

```csharp
using PgClient;

var parameters = new ConnectionParameters
{
    Hostname = "localhost",
    Port = 5432,
    Username = "postgres",
    Password = "postgres",
    Database = "postgres",
    ApplicationName = "MyApp",
};

await using var connection = new PgConnection(parameters);
await connection.ConnectAsync();

await using var reader = await connection.ExecuteReaderAsync(
    "SELECT id, name FROM users WHERE id = $1",
    [PgParameter.Int4(42)]);

while (await reader.ReadAsync())
{
    Console.WriteLine($"{reader.GetInt32(0)} {reader.GetString(1)}");
}
```

## Pooling

Use `PgDataSource` for a shared pool (one per host/db/user combo):

```csharp
await using var source = new PgDataSource(parameters);
await using var conn = await source.OpenConnectionAsync();
await conn.ExecuteNonQueryAsync("INSERT INTO t VALUES (1)");
```

## Connection string

`PgConnectionStringParser` accepts Npgsql-compatible keys:

```
Host=localhost;Port=5432;Username=postgres;Password=secret;Database=app;
SSL Mode=Require;Maximum Pool Size=50;Command Timeout=30;Max Auto Prepare=32
```

## ADO.NET

```csharp
using var conn = new PgDbConnection(connectionString);
await conn.OpenAsync();
using var cmd = new PgDbCommand("SELECT 1", conn);
var result = (int)(await cmd.ExecuteScalarAsync())!;
```

## Type mapping

| Postgres        | CLR                     |
| --------------- | ----------------------- |
| bool            | `bool`                  |
| int2/int4/int8  | `short`/`int`/`long`    |
| float4/float8   | `float`/`double`        |
| numeric         | `decimal`               |
| text/varchar    | `string`                |
| uuid            | `Guid`                  |
| bytea           | `byte[]`                |
| timestamp[tz]   | `DateTime`              |
| date            | `DateOnly`              |
| json/jsonb      | `string`                |
| array types     | typed `T[]`             |

## Building

```bash
dotnet build
dotnet test tests/PgClient.Tests/PgClient.Tests.csproj
```

Integration tests require a running Postgres. Set:

```
PGCLIENT_TEST_CONN=host;port;user;password;database
```

## Benchmarks

The `benchmarks/PgClient.Benchmarks` project uses BenchmarkDotNet to measure the
core hot paths of the client:

| Benchmark                    | What it measures                                             |
| ---------------------------- | ------------------------------------------------------------ |
| `SimpleQueryBenchmark`       | Round-trip cost of the simple query protocol.                |
| `ExtendedQueryBenchmark`     | Parse/Bind/Execute with the prepared-statement cache warm.   |
| `MultiRowReadBenchmark`      | Streaming throughput of the data reader over N rows.         |
| `ConnectionOpenBenchmark`    | Cost of TCP + startup + auth + parameter negotiation.        |
| `PoolRentReturnBenchmark`    | Pool rent/return with and without `DISCARD ALL` on release.  |
| `BufferReaderBenchmark`      | Primitive parsing surface used inside every row decode.      |

Run everything (requires a live Postgres reachable via the `PG*` env vars, except
`BufferReaderBenchmark` which is self-contained):

```bash
PGHOST=localhost PGUSER=postgres PGPASSWORD=... PGDATABASE=postgres \
  dotnet run -c Release --project benchmarks/PgClient.Benchmarks -- --filter '*'
```

Run one class:

```bash
dotnet run -c Release --project benchmarks/PgClient.Benchmarks -- --filter '*BufferReader*'
```

Results are written to `BenchmarkDotNet.Artifacts/`.

## Docker

A multi-stage [Dockerfile](Dockerfile) and [docker-compose.yml](docker-compose.yml)
are provided for reproducible sample runs, benchmarking, and NuGet packaging.

Start Postgres and the sample together:

```bash
docker compose up --build sample
```

Run the benchmark suite against the compose-managed Postgres (results are copied
back to `./BenchmarkDotNet.Artifacts` via a bind mount):

```bash
docker compose --profile benchmarks run --rm benchmarks --filter '*'
```

Build only the NuGet package image and extract the `.nupkg`:

```bash
docker build --target nuget -o ./artifacts .
```

Build just Postgres for local `dotnet run`:

```bash
docker compose up -d postgres
```

## License

MIT. See [LICENSE](LICENSE).
