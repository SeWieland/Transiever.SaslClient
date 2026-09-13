# Transiever.SaslClient

`Transiever.SaslClient` provides dependency-free .NET 10 SASL client mechanisms.
It owns message generation and proof validation; the host owns transport, framing, and TLS evidence.

Supported mechanisms are PLAIN, SCRAM-SHA-256, SCRAM-SHA-256-PLUS, OAUTHBEARER, and EXTERNAL.
SCRAM inputs remain printable ASCII and SCRAM-SHA-256-PLUS supports the `tls-server-end-point` binding supplied by a verified TLS 1.2 host.
The package does not acquire, refresh, store, or persist credentials.

Create a mechanism for an attempt after the host has verified its transport requirements:

```csharp
ISaslMechanism mechanism = new SaslPlainAuthenticator(userName, password);
ReadOnlyMemory<byte>? initialResponse = await mechanism.GetInitialResponseAsync(cancellationToken);
```

The host sends the response using its protocol framing, then calls `CompleteAsync` after success or `Abort` after failure.
Returned buffers belong to the mechanism and may be cleared during cleanup.
See the [authentication guide](https://github.com/SeWieland/Transiever.SaslClient/blob/main/docs/authentication.md) for the full lifecycle, security requirements, and mechanism limits.
