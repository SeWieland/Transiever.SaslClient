# Transiever.SaslClient

`Transiever.SaslClient` is a focused .NET 10 library for protocol-independent
SASL client mechanisms.
It produces and verifies SASL messages and proofs for a host protocol client;
it does not open connections or manage credentials.

## Install

```bash
dotnet add package Transiever.SaslClient
```

The package supports PLAIN, SCRAM-SHA-256, SCRAM-SHA-256-PLUS, OAUTHBEARER,
and certificate-backed EXTERNAL.
Production code uses only .NET runtime libraries.

## Boundary

The host supplies decoded challenge bytes; the mechanism owns returned response buffers until completion or abort.
It applies its protocol's framing and Base64 encoding.
The host must establish trustworthy protected transport and certificate
evidence before invoking a mechanism.
For SCRAM-SHA-256-PLUS, it supplies attempt-owned
`tls-server-end-point` binding bytes immediately before the exchange.

This library does not acquire, refresh, store, or revoke OAuth tokens; manage
certificates; select mechanisms; or implement a network protocol.

See the [authentication guide](docs/authentication.md) for lifecycle,
security, memory ownership, and failure behavior.
The [architecture guide](docs/architecture.md) describes the host boundary,
and [testing](docs/testing.md) describes offline conformance coverage.

## Development

```bash
dotnet restore Transiever.SaslClient.slnx
dotnet build Transiever.SaslClient.slnx --configuration Release --no-restore
dotnet test Transiever.SaslClient.slnx --configuration Release --no-build
dotnet pack src/Transiever.SaslClient/Transiever.SaslClient.csproj --configuration Release --no-build
```

## Publication

Stable releases come from `main`; beta prereleases come from `dev`.
GitHub Actions publish the library package to NuGet.org using trusted
publishing.
