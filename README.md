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

## Documentation Map

Start here, then follow the focused guides:

* [library guide](src/Transiever.SaslClient/README.md) for public API and package usage.
* [authentication](docs/authentication.md) for mechanism lifecycle, security, memory ownership, and failures.
* [architecture](docs/architecture.md) for the host boundary and responsibility split.
* [testing](docs/testing.md) for deterministic offline test policy.

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

## AI usage

Transiever is a personal hobby project created to solve practical problems I have encountered myself.

AI is used heavily throughout its development. It supports research, design exploration, implementation, debugging, and documentation.

The project is developed using test-driven development and reviewed by a human, me. Its direction, behavior, and quality remain guided by the problems it is intended to solve.
