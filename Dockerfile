# syntax=docker/dockerfile:1.7
# Multi-stage build for the PgClient library, sample, and benchmarks.
#
# Build stages:
#   * `build` — restores + compiles the library and produces a NuGet package.
#   * `sample` — publishes and runs samples/PgClient.Sample as the default entrypoint.
#   * `benchmarks` — publishes and runs benchmarks/PgClient.Benchmarks.
#   * `nuget` — thin export stage that only carries the .nupkg for CI extraction.
#
# Usage:
#   docker build -t pgclient:sample --target sample .
#   docker build -t pgclient:bench   --target benchmarks .
#   docker build -t pgclient:nuget   --target nuget .
#
ARG DOTNET_SDK_VERSION=9.0
ARG DOTNET_RUNTIME_VERSION=9.0

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_SDK_VERSION} AS build
WORKDIR /src

# Restore separately so the NuGet layer is cached whenever csproj files are unchanged.
COPY Directory.Build.props PgClient.sln ./
COPY PgClient/PgClient.csproj                          PgClient/
COPY tests/PgClient.Tests/PgClient.Tests.csproj        tests/PgClient.Tests/
COPY samples/PgClient.Sample/PgClient.Sample.csproj    samples/PgClient.Sample/
COPY benchmarks/PgClient.Benchmarks/PgClient.Benchmarks.csproj benchmarks/PgClient.Benchmarks/
RUN dotnet restore PgClient.sln

# Copy the rest of the tree and produce a NuGet package.
COPY . .
RUN dotnet build   PgClient/PgClient.csproj -c Release --no-restore \
 && dotnet pack    PgClient/PgClient.csproj -c Release --no-build --output /out/nuget

# --- Sample runtime image ------------------------------------------------------
FROM build AS publish-sample
RUN dotnet publish samples/PgClient.Sample/PgClient.Sample.csproj \
    -c Release --no-restore -o /app/sample

FROM mcr.microsoft.com/dotnet/runtime:${DOTNET_RUNTIME_VERSION} AS sample
WORKDIR /app
COPY --from=publish-sample /app/sample ./
ENV DOTNET_NOLOGO=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1
ENTRYPOINT ["dotnet", "PgClient.Sample.dll"]

# --- Benchmark runtime image ---------------------------------------------------
# Benchmarks need the SDK because BenchmarkDotNet emits and JIT-compiles code at runtime.
FROM build AS benchmarks
WORKDIR /src/benchmarks/PgClient.Benchmarks
ENV DOTNET_NOLOGO=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    PGHOST=postgres \
    PGPORT=5432 \
    PGUSER=pgclient \
    PGPASSWORD=pgclient \
    PGDATABASE=pgclient
ENTRYPOINT ["dotnet", "run", "-c", "Release", "--no-restore", "--"]
CMD ["--filter", "*"]

# --- NuGet-only export ---------------------------------------------------------
FROM scratch AS nuget
COPY --from=build /out/nuget/ /
