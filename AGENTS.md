# AGENTS.md

## Project boundary

`Transiever.SaslClient` is a protocol-only .NET library for SASL client
messages and proofs.
It owns the mechanism exchange callbacks, validation, proof computation, and
safe failure contracts for the supported mechanisms.
It does not own sockets, TLS, certificate validation, ManageSieve framing,
credential storage, OAuth acquisition, provider policy, or user login flows.

The library targets `net10.0`, enables nullable reference types and implicit
global usings, and must remain usable without this workspace or a sibling
checkout.

## Agent index

```text
Transiever.SaslClient.slnx
docs/authentication.md
docs/architecture.md
docs/testing.md
src/Transiever.SaslClient/
src/Transiever.SaslClient.UnitTest/
```

## Canonical docs

| Topic | Owner |
| --- | --- |
| Public mechanism API and package usage | `src/Transiever.SaslClient/README.md` |
| Mechanism lifecycle, security, memory, and failures | `docs/authentication.md` |
| Host boundary and responsibility split | `docs/architecture.md` |
| Deterministic test and live-provider policy | `docs/testing.md` |
| Public overview and development commands | `README.md` |
| Repository boundary, validation, and release workflow | `AGENTS.md` |

Update the focused owner for a behavior change instead of duplicating the
same contract across every document.

## Validation

```bash
dotnet restore Transiever.SaslClient.slnx
dotnet build Transiever.SaslClient.slnx --configuration Release --no-restore
dotnet test Transiever.SaslClient.slnx --configuration Release --no-build
dotnet pack src/Transiever.SaslClient/Transiever.SaslClient.csproj --configuration Release --no-build
```

Tests are deterministic and offline.
Provider credentials, live servers, and sibling repositories are never needed
for the normal build or test path.

## Non-negotiables

The supported mechanisms are PLAIN, SCRAM-SHA-256, SCRAM-SHA-256-PLUS,
OAUTHBEARER, and certificate-backed EXTERNAL.
Do not add networking, credential persistence, OAuth HTTP flows, provider SDKs,
mechanism discovery, or a server implementation to this package.

Transport protection is required by default.
The host is responsible for verified TLS and certificate evidence, and supplies
attempt-owned channel-binding bytes immediately before a PLUS exchange.
The mechanism must fail closed when binding is absent, empty, unsupported,
repeated, or late.

Keep authentication diagnostics fixed and redacted.
Do not expose credentials, raw SASL messages, private key material, or server
prose in exceptions or logs.
Preserve best-effort clearing of mutable buffers without promising erasure of
immutable strings or runtime, framework, transport, or server copies.

SCRAM remains ASCII-only and PLUS uses the existing TLS 1.2
`tls-server-end-point` profile.
Expanding those boundaries requires separate design work.

## Release

GitHub Actions run repository-local CI.
Releases are manually dispatched from `main` for stable versions or `dev` for
beta versions.
NuGet publishing uses GitHub OIDC trusted publishing through `NuGet/login`;
do not add a long-lived `NUGET_TOKEN` or `NUGET_API_KEY` secret.
This repository publishes only the library package and has no executable
release assets.
