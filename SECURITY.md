# Security Policy

## Supported versions

Only the latest `0.x` preview is supported until `1.0` ships.

## Reporting a vulnerability

Please **do not** open a public GitHub issue. Instead, email the maintainer
listed on the NuGet package page with:

- A description of the issue and its impact.
- A minimal reproduction if possible.
- Whether you would like credit in the advisory.

We aim to acknowledge reports within 5 business days and to publish a fix or a
mitigating workaround as soon as practical.

## Handling of credentials

- `ConnectionParameters.ToString()` redacts the password.
- The library never logs credentials in `ILogger` output.
- `TrustServerCertificate = true` and `SslMode = Disable` are convenience knobs
  for local development. Production deployments should use `Require` or
  stronger and rely on a proper certificate chain.
