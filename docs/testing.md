# Testing

The repository's normal test path is deterministic and offline.
It does not require a mail server, provider account, OAuth token, certificate
file, Docker, or a sibling checkout.

## Required checks

Run from the repository root:

```bash
dotnet restore Transiever.SaslClient.slnx
dotnet build Transiever.SaslClient.slnx --configuration Release --no-restore
dotnet test Transiever.SaslClient.slnx --configuration Release --no-build
dotnet pack src/Transiever.SaslClient/Transiever.SaslClient.csproj --configuration Release --no-build
```

Before publication, restore the packed artifact from an explicit temporary
package source; after publication, verify normal public-source restore.
The consumer must not reference ManageSieve or a sibling source project.
Inspect package dependency metadata to confirm that production dependencies
are limited to the .NET runtime.

## Conformance coverage

Mechanism tests use synthetic credentials, deterministic nonces where needed,
and in-memory challenge sequences.
They cover exact initial and challenge responses, known-answer SCRAM proofs,
strict parsing, message limits, proof verification, cancellation, lifecycle
ordering, null-versus-empty data, and redacted failures.

PLUS tests cover the GS2 header, raw endpoint-binding bytes, proof verification,
and fail-closed behavior for invalid binding input.
Certificate-hash derivation and TLS-version enforcement are tested by the host
protocol library, which owns the verified transport.
OAUTHBEARER tests cover RFC 7628 framing, actual `0x01` separators, bounded
strict JSON error parsing, safe error fields, and the fixed dummy response.
EXTERNAL tests cover empty and UTF-8 identities, strict bounds, and the
certificate-backed contract without installing or exporting private keys.

Buffer observations may verify best-effort clearing of mutable arrays.
Tests must not claim that immutable strings, runtime copies, transport buffers,
or server memory can be erased.

## Live interoperability

This package has no live-provider test suite.
Host protocol libraries own live interoperability checks and must keep them
explicitly enabled, outside normal CI, and free of persisted or logged real
credentials or token values.
