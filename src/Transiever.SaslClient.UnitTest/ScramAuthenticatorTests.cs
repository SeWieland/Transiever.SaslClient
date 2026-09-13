using System.Text;
using Transiever.SaslClient;

namespace Transiever.SaslClient.UnitTest;

public sealed class ScramAuthenticatorTests
{
    private const string ClientNonce = "rOprNGfwEbeRWgbNEkqO";
    private const string ServerNonce = ClientNonce + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    private const string ServerFirst =
        "r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    private const string ServerFinal = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    [Fact]
    public async Task Rfc7677_vector_generates_and_validates_the_expected_proof()
    {
        var authenticator = new SaslScramSha256Authenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => ClientNonce);

        Assert.Equal(
            "n,,n=user,r=rOprNGfwEbeRWgbNEkqO"u8.ToArray(),
            (await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken))?.ToArray());
        Assert.Equal(
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="u8.ToArray(),
            (await authenticator.RespondAsync(Encoding.UTF8.GetBytes(ServerFirst), TestContext.Current.CancellationToken)).ToArray());

        await authenticator.CompleteAsync(Encoding.UTF8.GetBytes(ServerFinal), TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Server_first_rejects_reordered_duplicate_and_reserved_extensions()
    {
        var authenticator = new SaslScramSha256Authenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => ClientNonce);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        foreach (string invalid in new[]
        {
            "s=W22ZaJ0SNY7soEsUEjb6gQ==,r=" + ServerNonce + ",i=4096",
            "r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,r=again",
            "r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,m=required"
        })
        {
            SaslAuthenticationException exception = await Assert.ThrowsAsync<SaslAuthenticationException>(
                () => authenticator.RespondAsync(Encoding.UTF8.GetBytes(invalid), TestContext.Current.CancellationToken).AsTask());
            Assert.Equal("SCRAM-SHA-256 authentication failed.", exception.Message);
            authenticator.Abort();
            authenticator = new SaslScramSha256Authenticator(
                "user", "pencil", authorizationIdentity: null, nonceFactory: () => ClientNonce);
            await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task Completion_rejects_a_wrong_server_signature_and_clears_buffers()
    {
        var authenticator = new SaslScramSha256Authenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => ClientNonce);
        ReadOnlyMemory<byte> initial = (await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken))!.Value;
        ReadOnlyMemory<byte> proof = await authenticator.RespondAsync(Encoding.UTF8.GetBytes(ServerFirst), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.CompleteAsync(
                "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="u8.ToArray(),
                TestContext.Current.CancellationToken).AsTask());

        Assert.All(initial.ToArray(), value => Assert.Equal(0, value));
        Assert.All(proof.ToArray(), value => Assert.Equal(0, value));
    }

    [Fact]
    public void Constructor_rejects_non_ascii_or_oversized_scram_inputs()
    {
        Assert.Throws<ArgumentNullException>(() => new SaslScramSha256Authenticator(null!, "p"));
        Assert.Throws<ArgumentException>(() => new SaslScramSha256Authenticator(string.Empty, "p"));
        Assert.Throws<ArgumentException>(() => new SaslScramSha256Authenticator("usér", "p"));
        Assert.Throws<ArgumentException>(() => new SaslScramSha256Authenticator("u", new string('a', 1025)));
    }

    [Theory]
    [InlineData("r=wrong,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=" + ServerNonce + ",s=not-base64!,i=4096")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4095")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=1000001")]
    public async Task Server_first_rejects_invalid_nonce_salt_and_iteration_bounds(string message)
    {
        var authenticator = NewScram();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        SaslAuthenticationException exception = await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.RespondAsync(Encoding.UTF8.GetBytes(message), TestContext.Current.CancellationToken).AsTask());

        Assert.Equal("SCRAM-SHA-256 authentication failed.", exception.Message);
    }

    [Fact]
    public async Task Server_first_rejects_oversized_salt_and_message()
    {
        foreach (string message in new[]
        {
            $"r={ServerNonce},s={Convert.ToBase64String(new byte[1025])},i=4096",
            new string('a', 16_385)
        })
        {
            var authenticator = NewScram();
            await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
            await Assert.ThrowsAsync<SaslAuthenticationException>(
                () => authenticator.RespondAsync(Encoding.UTF8.GetBytes(message), TestContext.Current.CancellationToken).AsTask());
        }
    }

    [Fact]
    public async Task Authorization_identity_is_escaped_and_empty_identity_is_omitted()
    {
        var escaped = new SaslScramSha256Authenticator(
            "us,er", "pencil", "auth=z,id", () => ClientNonce);
        Assert.Equal(
            "n,a=auth=3Dz=2Cid,n=us=2Cer,r=rOprNGfwEbeRWgbNEkqO"u8.ToArray(),
            (await escaped.GetInitialResponseAsync(TestContext.Current.CancellationToken))?.ToArray());

        var omitted = new SaslScramSha256Authenticator(
            "user", "pencil", string.Empty, () => ClientNonce);
        Assert.Equal(
            "n,,n=user,r=rOprNGfwEbeRWgbNEkqO"u8.ToArray(),
            (await omitted.GetInitialResponseAsync(TestContext.Current.CancellationToken))?.ToArray());
    }

    [Fact]
    public async Task Internal_exchange_clears_every_retained_buffer_on_abort()
    {
        var exchange = new ScramSha256Exchange("user", "pencil", null, ClientNonce);
        ReadOnlyMemory<byte> initial = (await exchange.GetInitialResponseAsync(CancellationToken.None))!.Value;
        ReadOnlyMemory<byte> proof = await exchange.RespondAsync(
            Encoding.UTF8.GetBytes(ServerFirst), CancellationToken.None);
        ReadOnlyMemory<byte> salt = exchange.Salt;
        ReadOnlyMemory<byte> signature = exchange.ExpectedServerSignature;

        exchange.Abort();

        Assert.All(initial.ToArray(), value => Assert.Equal(0, value));
        Assert.All(proof.ToArray(), value => Assert.Equal(0, value));
        Assert.All(salt.ToArray(), value => Assert.Equal(0, value));
        Assert.All(signature.ToArray(), value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task Completion_rejects_absent_server_data_and_poisons_the_exchange()
    {
        var authenticator = NewScram();
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        await authenticator.RespondAsync(Encoding.UTF8.GetBytes(ServerFirst), TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.CompleteAsync(null, TestContext.Current.CancellationToken).AsTask());
        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task Authorization_identity_is_included_in_the_proof()
    {
        var authenticator = new SaslScramSha256Authenticator(
            "us,er", "pencil", "auth=z,id", () => ClientNonce);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(Encoding.UTF8.GetBytes(ServerFirst), TestContext.Current.CancellationToken);

        Assert.Equal(
            Encoding.UTF8.GetBytes(
                "c=bixhPWF1dGg9M0R6PTJDaWQs,r=" + ServerNonce + ",p=zjLyhMiy6yjGzv1j0M7/XkeQbzxfTn5nPqLonAuPQx4="),
            response.ToArray());
    }

    [Fact]
    public void Empty_password_and_1024_byte_inputs_are_accepted()
    {
        string value = new('a', 1024);
        Assert.NotNull(new SaslScramSha256Authenticator(value, string.Empty, value, () => "nonce"));
    }

    [Fact]
    public void Nonce_factory_output_is_validated()
    {
        Assert.Throws<ArgumentException>(() => new SaslScramSha256Authenticator("u", "p", null, () => string.Empty));
        Assert.Throws<ArgumentException>(() => new SaslScramSha256Authenticator("u", "p", null, () => new string('a', 257)));
        Assert.Throws<ArgumentException>(() => new SaslScramSha256Authenticator("u", "p", null, () => "non,ce"));
    }

    [Fact]
    public async Task Cancelled_completion_clears_the_initial_response()
    {
        var authenticator = NewScram();
        ReadOnlyMemory<byte> response = (await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken))!.Value;
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => authenticator.CompleteAsync(null, cancellation.Token).AsTask());
        Assert.All(response.ToArray(), value => Assert.Equal(0, value));
    }

    private static SaslScramSha256Authenticator NewScram() =>
        new("user", "pencil", authorizationIdentity: null, nonceFactory: () => ClientNonce);
}
