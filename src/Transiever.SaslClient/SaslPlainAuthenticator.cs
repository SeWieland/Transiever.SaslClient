using System.Security.Cryptography;
using System.Text;

namespace Transiever.SaslClient;

/// <summary>
/// SASL PLAIN authenticator.
/// </summary>
public sealed class SaslPlainAuthenticator(
    string userName,
    string password,
    string? authorizationIdentity = null)
    : ISaslMechanism
{
    private byte[]? _response;

    /// <inheritdoc />
    public string Mechanism => "PLAIN";

    /// <inheritdoc />
    public bool AllowsUnprotectedConnection => false;

    /// <inheritdoc />
    public ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ClearResponse();
        byte[] authenticationIdentity = Encoding.UTF8.GetBytes(userName);
        byte[] secret = Encoding.UTF8.GetBytes(password);
        byte[] authorization = Encoding.UTF8.GetBytes(authorizationIdentity ?? string.Empty);
        byte[] credentialResponse = new byte[
            authorization.Length + authenticationIdentity.Length + secret.Length + 2];

        try
        {
            authorization.CopyTo(credentialResponse, 0);
            authenticationIdentity.CopyTo(credentialResponse, authorization.Length + 1);
            secret.CopyTo(
                credentialResponse,
                authorization.Length + authenticationIdentity.Length + 2);
            _response = credentialResponse;
            return ValueTask.FromResult<ReadOnlyMemory<byte>?>(credentialResponse);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(credentialResponse);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authenticationIdentity);
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(authorization);
        }
    }

    /// <inheritdoc />
    public ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new SaslAuthenticationException(
            "SASL PLAIN does not support additional server challenges.");
    }

    /// <inheritdoc />
    public ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken = default)
    {
        ClearResponse();
        return serverData is null
            ? ValueTask.CompletedTask
            : ValueTask.FromException(
                new SaslAuthenticationException(
                    "SASL PLAIN does not support server-final data."));
    }

    /// <inheritdoc />
    public void Abort() => ClearResponse();

    private void ClearResponse()
    {
        byte[]? responseToClear = Interlocked.Exchange(ref _response, null);
        if (responseToClear is not null)
        {
            CryptographicOperations.ZeroMemory(responseToClear);
        }
    }
}
