# Contributing

Thanks for your interest in `PgClient`!

## Reporting issues

Please include:
- .NET version (`dotnet --info`)
- OS
- Postgres version
- A minimal reproduction

## Building locally

```bash
dotnet build
dotnet test tests/PgClient.Tests/PgClient.Tests.csproj
```

Integration tests require a running Postgres and the `PGCLIENT_TEST_CONN`
environment variable of the form `host;port;user;password;database`.

## Coding conventions

- `nullable enable` throughout.
- `Release` builds treat warnings as errors — keep the tree clean.
- Public API changes require a note in `CHANGELOG.md` under `[Unreleased]`.
- Prefer `Span<byte>`, `stackalloc`, `ArrayPool<byte>` over per-call allocation
  on hot paths.
- Use `ConfigureAwait(false)` inside library code.

## Commit style

Short, imperative summary. Optional body wrapping at 72 chars.

## PR checklist

- [ ] Tests added or updated.
- [ ] `dotnet format --verify-no-changes` passes.
- [ ] `dotnet build -c Release` passes with zero warnings.
- [ ] `CHANGELOG.md` updated.
