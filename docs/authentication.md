# Authentication

This guide defines the protocol-neutral mechanism contract and its security
boundary.
Protocol framing, transport recovery, and session state belong to the host
protocol client.

## Supported mechanisms

The package supports the existing client behavior for:

* `PLAIN`.
* `SCRAM-SHA-256`.
* `SCRAM-SHA-256-PLUS`.
* `OAUTHBEARER`.
* Certificate-backed `EXTERNAL`.

Protected transport is required by default.
EXTERNAL requires the host to establish mutual TLS and prove that a usable
caller certificate was presented.
The package does not validate a server certificate or inspect a connection.

## PLAIN

`PLAIN` produces the UTF-8 sequence `authorization identity`, NUL,
`authentication identity`, NUL, `password`.
An omitted or empty authorization identity produces an empty first field.
The mechanism requires protected transport and accepts no challenges or
server-final data.
The host applies its protocol's Base64 framing; Base64 is not encryption.

## Callback lifecycle

An authentication attempt has three asynchronous callbacks and one synchronous
cleanup operation:

1. Get an optional initial response.
2. Respond to each decoded server challenge.
3. Complete with optional decoded final data.
4. Abort after an unsuccessful attempt; `Abort` is synchronous and local.

The host must call completion exactly once after the protocol reports success.
Abort is synchronous local cleanup and does not send a wire-level SASL
cancellation response.
The host passes its cancellation token to every asynchronous callback.
The mechanism owns response buffers returned by its callbacks until completion
or abort.

`null` means that initial or final data is absent.
An empty byte sequence means data is present and empty; hosts must preserve that
distinction when framing a protocol command.

SCRAM, OAUTHBEARER, and EXTERNAL reject repeated or out-of-order callbacks according to their lifecycle contracts.
PLAIN preserves its existing reusable behavior: another initial-response call clears the previous response and creates a new one, including after completion or abort.
PLAIN completion always clears the response and rejects present final data, but does not check cancellation; its initial-response and challenge callbacks do check cancellation.
The host remains responsible for rejecting malformed protocol framing before a
challenge reaches the mechanism.

## Channel binding

`SCRAM-SHA-256-PLUS` must never silently downgrade to unbound SCRAM.
The host supplies non-empty, attempt-owned `tls-server-end-point` bytes obtained
from the verified TLS 1.2 connection immediately before the first response.
Missing, empty, unsupported, repeated, or late binding input is a PLUS failure.

The current implementation accepts the existing TLS 1.2 certificate hash
profile.
TLS 1.3 and `tls-exporter` require a separate compatibility decision.

## Mechanism-specific limits

SCRAM user name, password, and optional authorization identity are printable
ASCII and at most 1,024 bytes each.
The user name is non-empty; the password may be empty; an empty authorization
identity is treated as absent.
Commas and equals signs in identities use the `=2C` and `=3D` escapes.
Unicode normalization and SASLprep are not included.

Production nonces contain 18 random bytes encoded with standard Base64.
The deterministic nonce seam used by offline tests is internal.
The first server challenge must contain ordered, unique `r=`, `s=`, and `i=`
fields, followed only by syntactically valid optional extensions.
Mandatory `m=` extensions, missing, duplicate, reordered, or malformed
mandatory fields are rejected, as are assigned attribute names where only
unassigned extensions are permitted.
The server nonce is printable, contains the exact client nonce as a prefix,
adds at least one character, and is at most 256 bytes.
The decoded salt is 1 to 1,024 bytes, and the iteration count is 4,096 to
1,000,000.
Complete SCRAM messages are 1 to 16,384 UTF-8 bytes.
Base64 is strict and canonical: whitespace, invalid alphabet, misplaced
padding, and alternate encodings are rejected.
Proof derivation uses SHA-256 PBKDF2 and HMAC over the exact SCRAM transcript,
and the 32-byte server signature is compared in constant time.
Server errors, malformed or replayed messages, extra challenges, and invalid
proofs use the fixed redacted `SCRAM-SHA-256 authentication failed.` diagnostic.

OAUTHBEARER accepts a caller-supplied in-memory RFC 6750 `b64token` of 1 to
16,384 characters.
Padding is allowed only at the end and at least one token character is
required.
The host value is non-empty ASCII, at most 255 bytes, and contains no control
characters; internationalized names must already be IDNA A-labels.
The port is 1 through 65,535.
The optional authorization identity is strict UTF-8, at most 1,024 bytes, and
contains no NUL.
Its initial response uses `n,,` or the escaped `n,a=<authzid>,` GS2 prefix,
actual single-byte `0x01` separators, `host=`, `port=`, and
`auth=Bearer <token>` fields, followed by an empty field.

An OAuth error challenge is 1 to 16,384 bytes of strict UTF-8 JSON with an
object root and maximum depth 8.
Only the exact case-sensitive properties `status`, `scope`, and
`openid-configuration` are recognized.
`status` is required, non-empty, and at most 128 UTF-8 bytes; `scope` is
optional and at most 4,096 UTF-8 bytes; `openid-configuration` is optional and
at most 2,048 UTF-8 bytes.
Recognized values must be strings, may not be duplicated, and may not echo the
access token.
The optional configuration value must be an absolute HTTPS URL without userinfo
or a fragment.
Unknown properties are discarded.
Malformed JSON, invalid UTF-8, wrong value types, duplicate recognized
properties, or out-of-range values use the fixed redacted
`OAUTHBEARER authentication failed.` diagnostic.
After a valid error challenge the mechanism returns exactly one dummy byte,
`0x01`, and exposes only the safe parsed error record.
It never fetches an OpenID configuration URL or acquires, refreshes, revokes,
or stores a token.

EXTERNAL encodes the caller's authorization identity as strict UTF-8.
An omitted or empty identity asks the server to use the identity associated
with the TLS credentials.
Certificate enrollment and private-key storage remain host responsibilities.

## Memory and diagnostics

The host owns decoded server challenge and final-data buffers and clears them
after callbacks.
The mechanism clears mutable response, proof, and password-derived buffers on
completion or abort on a best-effort basis.
Returned response buffers remain mechanism-owned; the host must not mutate or
retain them after the attempt ends.

Managed code cannot guarantee erasure of immutable strings, garbage-collector
or runtime copies, framework and operating-system buffers, transport captures,
server memory, or copied test transcripts.

Failures use fixed, redacted diagnostics.
They must not include credentials, authorization identities, raw SASL data,
proofs, nonces, salts, private keys, certificate subjects, server prose, or
callback exception text.
The protocol host may translate these failures into its own safe exception
types and response-code contract.
