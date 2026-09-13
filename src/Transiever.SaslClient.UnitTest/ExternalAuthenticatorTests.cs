using Transiever.SaslClient;

namespace Transiever.SaslClient.UnitTest;

public sealed class ExternalAuthenticatorTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("alice@example.com", "616C696365406578616D706C652E636F6D")]
    [InlineData("Jörg", "4AC3B67267")]
    public async Task Initial_response_is_strict_utf8(string? identity, string expectedHex)
    {
        var authenticator = new SaslExternalAuthenticator(identity);

        ReadOnlyMemory<byte> response = (await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken))!.Value;

        Assert.Equal(Convert.FromHexString(expectedHex), response.ToArray());
        Assert.True(authenticator.RequiresClientCertificate);
    }

    [Fact]
    public async Task Challenges_and_completion_data_are_rejected()
    {
        var authenticator = new SaslExternalAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.RespondAsync("challenge"u8.ToArray(), TestContext.Current.CancellationToken).AsTask());
        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.CompleteAsync(ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public void Identity_limits_and_lifecycle_are_enforced()
    {
        Assert.Throws<ArgumentException>(() => new SaslExternalAuthenticator("id\0"));
        Assert.Throws<ArgumentException>(() => new SaslExternalAuthenticator(new string('é', 513)));
    }

    [Fact]
    public async Task Identity_accepts_the_1024_utf8_octet_boundary()
    {
        var authenticator = new SaslExternalAuthenticator(new string('é', 512));

        ReadOnlyMemory<byte> response = (await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken))!.Value;

        Assert.Equal(1024, response.Length);
        await authenticator.CompleteAsync(null, TestContext.Current.CancellationToken);
        Assert.All(response.ToArray(), value => Assert.Equal(0, value));
    }

    [Fact]
    public void Invalid_utf16_is_rejected_without_an_inner_exception_or_identity_echo()
    {
        string identity = new('\uD800', 1);
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => new SaslExternalAuthenticator(identity));

        Assert.Null(exception.InnerException);
        Assert.DoesNotContain(identity, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cancellation_is_propagated_and_abort_clears_the_response()
    {
        var authenticator = new SaslExternalAuthenticator("Jörg");
        ReadOnlyMemory<byte> response = (await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken))!.Value;
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => authenticator.CompleteAsync(null, cancellation.Token).AsTask());
        authenticator.Abort();
        Assert.All(response.ToArray(), value => Assert.Equal(0, value));
    }
}
