# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Multi-target `net8.0` and `net9.0`.
- Repository hygiene: README, LICENSE, CHANGELOG, CONTRIBUTING, SECURITY,
  `.editorconfig`, `Directory.Build.props` with analyzers.
- Optional `ILogger` and `System.Diagnostics.Metrics.Meter` integration.
- `PgConnectionPool` prewarms to `MinPoolSize` on first rent and enforces
  `PoolWaitTimeout` when the pool is exhausted.
- `CommandTimeout` is now wired into every command via a linked
  `CancellationTokenSource`.
- `ConnectionParameters.NoResetOnClose` — skip `DISCARD ALL` when returning
  connections to the pool (recommended for PgBouncer transaction-pooling mode).
- TCP keepalive on the underlying `TcpClient`.
- `ConnectionParameters.ToString()` redacts the password.
- `PgConnection.ServerVersion` exposes the negotiated server version.

### Changed
- Library is no longer an `Exe`. `Program.cs`, `Test.cs`, `TestWorkingClient.cs`
  and the old `Benchmark/` folder have been removed from the packable project.
  The runnable sample now lives under `samples/PgClient.Sample`, and benchmarks
  under `benchmarks/PgClient.Benchmarks`.
- `BenchmarkDotNet` is no longer a runtime dependency of the library.

### Fixed
- `AuthenticationHandler._saltedPassword` is now initialised to avoid a null
  reference warning.
- ADO.NET `PgDbConnection.Close()` only fires `StateChange` when the state
  actually transitions.
- `PgConnection` moved into the `PgClient` namespace (no more global-namespace
  public types).
- Nullability annotations aligned with `DbConnection`/`DbCommand`/`DbParameter`
  base overrides so consumers of the ADO.NET wrapper don't see spurious warnings.

### CI
- Matrix build across `ubuntu-latest`, `windows-latest`, `macos-latest`.
- Integration tests fan out over PostgreSQL 13, 14, 15, 16 and 17.
- `dotnet format --verify-no-changes` gate on Linux.
- Cobertura coverage collection and Codecov upload.

### Benchmarks
- Expanded `PgClient.Benchmarks` with dedicated classes for the connection
  open path, pool rent/return, extended-query hot loop, multi-row streaming,
  and buffer-reader micro-benchmarks. Configuration is read from `PG*`
  environment variables.

### Docker
- Multi-stage `Dockerfile` with `sample`, `benchmarks`, and `nuget` targets.
- `docker-compose.yml` provisions a Postgres 16 service alongside the sample
  container, plus an opt-in `benchmarks` profile that runs BenchmarkDotNet
  against the same Postgres.
- `.dockerignore` excludes build artefacts, source-control, and IDE files.

## [0.1.0-preview] - initial

- Baseline PostgreSQL wire protocol client.
