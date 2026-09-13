using System.Text;
using Transiever.SaslClient;

namespace Transiever.SaslClient.UnitTest;

public sealed class MovedOAuthMechanismTests
{
    private static SaslOAuthBearerAuthenticator NewAuthenticator() =>
        new("caller-token", "host", 1);

    [Fact]
    public async Task Initial_response_uses_gs2_escaping_and_strict_utf8()
    {
        var authenticator = new SaslOAuthBearerAuthenticator(
            "token",
            "host.example",
            65_535,
            "a,b=é");

        ReadOnlyMemory<byte> response =
            (await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken)).GetValueOrDefault();

        Assert.Equal(
            "n,a=a=2Cb=3Dé,\u0001host=host.example\u0001port=65535\u0001auth=Bearer token\u0001\u0001"u8.ToArray(),
            response.ToArray());
    }

    [Fact]
    public async Task Initial_response_rejects_duplicate_initial_use()
    {
        var authenticator = NewAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        SaslAuthenticationException exception = await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("OAUTHBEARER authentication exchange has already been used.", exception.Message);
    }

    [Fact]
    public void Accepts_trailing_padding_and_boundary_token_size()
    {
        Assert.NotNull(new SaslOAuthBearerAuthenticator("abc+/._~-==", "host", 1));
        Assert.NotNull(new SaslOAuthBearerAuthenticator(new string('a', 16_384), "host", 65_535));
    }

    [Fact]
    public void Rejects_null_empty_or_invalid_tokens()
    {
        Assert.Throws<ArgumentNullException>(() => new SaslOAuthBearerAuthenticator(null!, "host", 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator(string.Empty, "host", 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("a=b=c", "host", 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("a?b", "host", 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator(new string('a', 16_385), "host", 1));
    }

    [Fact]
    public void Rejects_padding_only_tokens()
    {
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("=", "host", 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("==", "host", 1));
    }

    [Fact]
    public void Rejects_invalid_hosts_and_ports()
    {
        Assert.Throws<ArgumentNullException>(() => new SaslOAuthBearerAuthenticator("a", null!, 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("a", string.Empty, 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("a", "höst.example", 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("a", "host\0", 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("a", "host\n", 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("a", new string('a', 256), 1));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("a", new string('é', 128), 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SaslOAuthBearerAuthenticator("a", "host", 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SaslOAuthBearerAuthenticator("a", "host", 65_536));
    }

    [Fact]
    public void Accepts_255_byte_ascii_host()
    {
        Assert.NotNull(new SaslOAuthBearerAuthenticator("a", new string('a', 255), 1));
    }

    [Fact]
    public void Rejects_nul_authorization_identity_but_accepts_non_ascii_utf8()
    {
        Assert.NotNull(new SaslOAuthBearerAuthenticator("a", "host", 1));
        Assert.NotNull(new SaslOAuthBearerAuthenticator("a", "host", 1, string.Empty));
        Assert.NotNull(new SaslOAuthBearerAuthenticator("a", "host", 1, "délégation"));
        Assert.NotNull(new SaslOAuthBearerAuthenticator("a", "host", 1, new string('a', 1_024)));
        Assert.Throws<ArgumentException>(
            () => new SaslOAuthBearerAuthenticator("a", "host", 1, new string('a', 1_025)));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("a", "host", 1, "user\0id"));
        Assert.Throws<ArgumentException>(() => new SaslOAuthBearerAuthenticator("a", "host", 1, "\uD800"));
    }

    [Fact]
    public async Task Completion_accepts_only_without_server_data_and_rejects_reuse()
    {
        var authenticator = NewAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        await authenticator.CompleteAsync(null, TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.CompleteAsync(null, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task First_non_null_completion_does_not_consume_the_exchange()
    {
        var authenticator = NewAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.CompleteAsync(new byte[] { 1 }, TestContext.Current.CancellationToken).AsTask());
        await authenticator.CompleteAsync(null, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Abort_is_idempotent_and_rejects_callbacks()
    {
        var authenticator = NewAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        authenticator.Abort();
        authenticator.Abort();

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.RespondAsync("{}"u8.ToArray(), TestContext.Current.CancellationToken).AsTask());
        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.CompleteAsync(null, TestContext.Current.CancellationToken).AsTask());
        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task Error_rejects_duplicate_response_and_completion_after_error()
    {
        var authenticator = NewAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        ReadOnlyMemory<byte> dummy = await authenticator.RespondAsync(
            "{\"status\":\"ok\"}"u8.ToArray(), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.RespondAsync(
                "{\"status\":\"again\"}"u8.ToArray(), TestContext.Current.CancellationToken).AsTask());
        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.CompleteAsync(null, TestContext.Current.CancellationToken).AsTask());

        authenticator.Abort();
        Assert.Equal(new byte[] { 0 }, dummy.ToArray());
        Assert.NotNull(authenticator.ServerError);
    }

    [Fact]
    public async Task Error_rejects_malformed_shapes_bounds_urls_and_token_reflection()
    {
        string[] invalid =
        [
            "{}", "{\"status\":\"\"}", "{\"status\":null}", "{\"status\":1}",
            "{\"status\":\"ok\",\"status\":\"again\"}", "{\"status\":\"ok\",\"x\":}",
            "{\"status\":\"ok\"} trailing", "[\"status\"]", "{/* comment */\"status\":\"ok\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"http://example.com\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"/.well-known/openid-configuration\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"https://user@example.com\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"https://example.com/#fragment\"}",
            "{\"status\":\"caller-token\"}",
            "{\"status\":\"ok\",\"scope\":\"caller-token\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"https://example.com/caller-token\"}",
            "{\"status\":\"ok\",\"scope\":\"one\",\"scope\":\"two\"}",
            "{\"status\":\"ok\",\"openid-configuration\":\"https://a\",\"openid-configuration\":\"https://b\"}",
            $"{{\"status\":\"{new string('a', 129)}\"}}",
            $"{{\"status\":\"ok\",\"scope\":\"{new string('a', 4_097)}\"}}",
            $"{{\"status\":\"ok\",\"openid-configuration\":\"https://example.com/{new string('é', 1_014)}a\"}}",
            "{\"status\":\"ok\",\"nested\":{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":1}}}}}}}}}"
        ];

        foreach (string value in invalid)
        {
            var authenticator = NewAuthenticator();
            await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
            SaslAuthenticationException exception = await Assert.ThrowsAsync<SaslAuthenticationException>(
                () => authenticator.RespondAsync(
                    Encoding.UTF8.GetBytes(value), TestContext.Current.CancellationToken).AsTask());

            Assert.Equal("OAUTHBEARER authentication failed.", exception.Message);
            Assert.Null(exception.InnerException);
            Assert.Null(authenticator.ServerError);
            Assert.DoesNotContain(value, exception.ToString(), StringComparison.Ordinal);
        }

        var invalidUtf8 = NewAuthenticator();
        await invalidUtf8.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        byte[] invalidBytes =
            [(byte)'{', (byte)'"', (byte)'s', (byte)'t', (byte)'a', (byte)'t', (byte)'u', (byte)'s',
             (byte)'"', (byte)':', (byte)'"', 0xC3, (byte)'"', (byte)'}'];
        SaslAuthenticationException invalidUtf8Exception = await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => invalidUtf8.RespondAsync(invalidBytes, TestContext.Current.CancellationToken).AsTask());
        Assert.Equal("OAUTHBEARER authentication failed.", invalidUtf8Exception.Message);
        Assert.Null(invalidUtf8Exception.InnerException);
    }

    [Fact]
    public async Task Error_accepts_exact_multibyte_value_boundaries_and_discards_unknown_fields()
    {
        string status = new('é', 64);
        string scope = new('é', 2_048);
        string configuration = "https://example.com/" + new string('é', 1_014);
        string json = $"{{\"unknown\":{{\"nested\":[1]}},\"status\":\"{status}\",\"scope\":\"{scope}\"," +
            $"\"openid-configuration\":\"{configuration}\"}}";
        var authenticator = NewAuthenticator();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            Encoding.UTF8.GetBytes(json), TestContext.Current.CancellationToken);

        Assert.Equal(new byte[] { 1 }, response.ToArray());
        Assert.Equal(status, authenticator.ServerError!.Status);
        Assert.Equal(scope, authenticator.ServerError.Scope);
        Assert.Equal(configuration, authenticator.ServerError.OpenIdConfiguration);
    }

    [Fact]
    public async Task Error_enforces_decoded_challenge_length_boundaries()
    {
        foreach (int length in new[] { 16_384, 16_385 })
        {
            var authenticator = NewAuthenticator();
            await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
            byte[] challenge = ChallengeWithLength(length);

            if (length == 16_384)
            {
                Assert.Equal(
                    new byte[] { 1 },
                    (await authenticator.RespondAsync(challenge, TestContext.Current.CancellationToken)).ToArray());
            }
            else
            {
                await Assert.ThrowsAsync<SaslAuthenticationException>(
                    () => authenticator.RespondAsync(
                        challenge, TestContext.Current.CancellationToken).AsTask());
            }
        }
    }

    private static byte[] ChallengeWithLength(int length)
    {
        const string prefix = "{\"status\":\"ok\",\"unknown\":\"";
        const string suffix = "\"}";
        return Encoding.UTF8.GetBytes(
            prefix + new string('a', length - Encoding.UTF8.GetByteCount(prefix + suffix)) + suffix);
    }
}
