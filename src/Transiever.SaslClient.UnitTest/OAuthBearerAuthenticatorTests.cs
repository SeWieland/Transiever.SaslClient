using System.Text;
using Transiever.SaslClient;

namespace Transiever.SaslClient.UnitTest;

public sealed class OAuthBearerAuthenticatorTests
{
    [Fact]
    public async Task Initial_response_uses_the_rfc7628_gs2_shape()
    {
        var authenticator = new SaslOAuthBearerAuthenticator(
            "token", "server.example.com", 4190, "user@example.com");

        ReadOnlyMemory<byte> response = (await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken))!.Value;

        Assert.Equal(
            "n,a=user@example.com,\u0001host=server.example.com\u0001port=4190\u0001auth=Bearer token\u0001\u0001"u8.ToArray(),
            response.ToArray());
    }

    [Fact]
    public async Task Error_challenge_exposes_only_the_safe_error_record_and_returns_dummy_byte()
    {
        var authenticator = new SaslOAuthBearerAuthenticator("token", "host", 1);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            "{\"status\":\"401\",\"scope\":\"mail\",\"openid-configuration\":\"https://example.com/.well-known\",\"unknown\":true}"u8.ToArray(),
            TestContext.Current.CancellationToken);

        Assert.Equal(new byte[] { 1 }, response.ToArray());
        Assert.Equal(new SaslOAuthBearerError("401", "mail", "https://example.com/.well-known"), authenticator.ServerError);
    }

    [Fact]
    public async Task Malformed_error_challenges_use_the_fixed_redacted_failure()
    {
        var authenticator = new SaslOAuthBearerAuthenticator("secret-token", "host", 1);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        SaslAuthenticationException exception = await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.RespondAsync("{\"scope\":1}"u8.ToArray(), TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("OAUTHBEARER authentication failed.", exception.Message);
        Assert.Null(authenticator.ServerError);
    }

    [Fact]
    public void Constructor_rejects_invalid_token_host_and_port()
    {
        Assert.Throws<ArgumentNullException>(() => new SaslOAuthBearerAuthenticator(null!, "host", 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("a?b", "host", 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("token", "höst", 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SaslOAuthBearerAuthenticator("token", "host", 0));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"status\":1}")]
    [InlineData("{\"status\":\"ok\",\"status\":\"again\"}")]
    [InlineData("{\"status\":\"ok\",\"openid-configuration\":\"http://example.com\"}")]
    [InlineData("{\"status\":\"caller-token\"}")]
    [InlineData("{\"status\":\"ok\",\"scope\":\"caller-token\"}")]
    public async Task Invalid_error_challenges_are_redacted(string challenge)
    {
        var authenticator = new SaslOAuthBearerAuthenticator("caller-token", "host", 1);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        SaslAuthenticationException exception = await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.RespondAsync(Encoding.UTF8.GetBytes(challenge), TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("OAUTHBEARER authentication failed.", exception.Message);
        Assert.Null(authenticator.ServerError);
    }

    [Fact]
    public async Task Completion_requires_absent_server_data_and_lifecycle_is_terminal()
    {
        var authenticator = new SaslOAuthBearerAuthenticator("token", "host", 1);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.CompleteAsync(ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken).AsTask());

        var completed = new SaslOAuthBearerAuthenticator("token", "host", 1);
        ReadOnlyMemory<byte> initial = (await completed.GetInitialResponseAsync(TestContext.Current.CancellationToken))!.Value;
        await completed.CompleteAsync(null, TestContext.Current.CancellationToken);
        Assert.All(initial.ToArray(), value => Assert.Equal(0, value));
        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => completed.GetInitialResponseAsync(TestContext.Current.CancellationToken).AsTask());
    }
}
