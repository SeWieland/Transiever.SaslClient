# Architecture

`Transiever.SaslClient` sits between a protocol client and its server:

```text
application
    -> protocol client (transport, TLS, framing)
        -> Transiever.SaslClient (messages and proofs)
            -> server
```

The package has no socket, stream, TLS, certificate, or ManageSieve dependency.
The host chooses a mechanism, checks the server advertisement, establishes
protected transport, and applies the protocol's framing and Base64 encoding.

## Exchange boundary

The mechanism contract is asynchronous and protocol-neutral:

1. The host asks for an optional initial response.
2. The host passes each decoded server challenge to the mechanism.
3. The mechanism returns a decoded response owned by the mechanism.
4. The host passes optional decoded final data for completion.
5. The host calls abort for an unsuccessful attempt.

Absent initial or final data remains distinct from present empty data.
Challenge and final-data buffers supplied by the host are valid only during the
callback.
The host clears its own decoded buffers after each callback.

Mechanisms never write to a network connection, interpret protocol response
codes, or decide whether a failed exchange can reuse a session.
Those decisions remain with the protocol client.

## Transport and identity responsibilities

Protected transport is the default requirement.
The host performs normal certificate validation and retains evidence that the
connection is the one it intended to authenticate.
EXTERNAL is limited to the existing certificate-backed TLS profile; this
package does not acquire, enroll, renew, import, or store certificates.

For SCRAM-SHA-256-PLUS, the host obtains the verified peer certificate's
`tls-server-end-point` binding immediately before the locked authentication
attempt and supplies those bytes to the mechanism.
The mechanism has no access to a socket and cannot prove how a caller obtained
the bytes, so the host must not reuse binding data from another connection or
attempt.

The current PLUS profile supports TLS 1.2 endpoint binding only.
TLS 1.3 `tls-exporter` support is outside this package's current boundary.

## Deliberate limits

The first release supports PLAIN, SCRAM-SHA-256, SCRAM-SHA-256-PLUS,
OAUTHBEARER, and EXTERNAL only.
SCRAM input remains ASCII-only and does not apply Unicode normalization or
SASLprep.
There is no server implementation, security layer, mechanism registry,
credential store, provider policy, OAuth HTTP client, or login UI.
