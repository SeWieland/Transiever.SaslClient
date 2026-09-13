namespace Transiever.SaslClient;

/// <summary>Raised when a SASL mechanism cannot process an exchange.</summary>
public sealed class SaslAuthenticationException : Exception
{
    /// <summary>Initializes an exception with the supplied diagnostic message.</summary>
    public SaslAuthenticationException(string message)
        : base(message)
    {
    }
}

/// <summary>Safe server data returned by an OAUTHBEARER error challenge.</summary>
public sealed record SaslOAuthBearerError(
    string Status,
    string? Scope,
    string? OpenIdConfiguration);

/// <summary>Supplies one attempt-bound channel binding to a SASL mechanism.</summary>
public interface ISaslChannelBindingMechanism
{
    /// <summary>Gets the channel binding type required by the mechanism.</summary>
    string ChannelBindingName { get; }

    /// <summary>Sets the binding bytes for the current authentication attempt.</summary>
    void SetChannelBinding(ReadOnlyMemory<byte> binding);
}
