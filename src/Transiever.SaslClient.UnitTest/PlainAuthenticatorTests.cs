using System.Text;
using Transiever.SaslClient;

namespace Transiever.SaslClient.UnitTest;

public sealed class PlainAuthenticatorTests
{
    [Fact]
    public async Task InitialResponse_contains_authorization_identity_user_and_password()
    {
        var authenticator = new SaslPlainAuthenticator("user", "secret", "authz");

        ReadOnlyMemory<byte>? response = await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        Assert.Equal("authz\0user\0secret"u8.ToArray(), response?.ToArray());
        Assert.Equal("PLAIN", authenticator.Mechanism);
        Assert.False(authenticator.AllowsUnprotectedConnection);
    }

    [Fact]
    public async Task Completion_and_abort_clear_the_owned_response()
    {
        var authenticator = new SaslPlainAuthenticator("user", "secret");
        ReadOnlyMemory<byte> response = (await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken))!.Value;

        await authenticator.CompleteAsync(null, TestContext.Current.CancellationToken);

        Assert.All(response.ToArray(), value => Assert.Equal(0, value));
        authenticator.Abort();
    }

    [Fact]
    public async Task Challenges_and_server_final_data_are_rejected()
    {
        var challenge = new SaslPlainAuthenticator("user", "secret");
        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => challenge.RespondAsync("challenge"u8.ToArray(), TestContext.Current.CancellationToken).AsTask());

        var completion = new SaslPlainAuthenticator("user", "secret");
        await completion.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => completion.CompleteAsync(ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken).AsTask());
    }
}
