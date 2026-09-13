using System.Text;
using Transiever.SaslClient;

namespace Transiever.SaslClient.UnitTest;

public sealed class MovedScramMechanismTests
{
    private const string ClientNonce = "rOprNGfwEbeRWgbNEkqO";
    private const string ServerNonce = ClientNonce + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    private const string RfcServerFirst = "r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    private const string AuthenticationFailure = "SCRAM-SHA-256 authentication failed.";
    [Theory]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=extension")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=a=b")]
    public async Task ScramServerFirst_accepts_ordered_fields_and_optional_extensions(string message)
    {
        SaslScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            Encoding.UTF8.GetBytes(message), TestContext.Current.CancellationToken);

        AssertClientFinal(response, ServerNonce);
    }

    [Theory]
    [InlineData('a')]
    [InlineData('c')]
    [InlineData('e')]
    [InlineData('n')]
    [InlineData('p')]
    [InlineData('v')]
    public async Task ScramServerFirst_rejects_assigned_attribute_as_extension(char name)
    {
        await AssertRejectedAsync(ServerFirst(extension: $"{name}=value"));
    }

    [Theory]
    [InlineData("s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=" + ServerNonce + ",i=4096")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==")]
    [InlineData("s=W22ZaJ0SNY7soEsUEjb6gQ==,r=" + ServerNonce + ",i=4096")]
    [InlineData("r=" + ServerNonce + ",i=4096,s=W22ZaJ0SNY7soEsUEjb6gQ==")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,r=again,i=4096")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,s=YQ==,i=4096")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,i=4097")]
    [InlineData("m=required,r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,xx=value")]
    [InlineData("r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=\0")]
    public async Task ScramServerFirst_rejects_missing_reordered_duplicate_or_invalid_attributes(
        string message)
    {
        await AssertRejectedAsync(Encoding.UTF8.GetBytes(message));
    }

    [Theory]
    [InlineData("r=wrongServer,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=" + ClientNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=" + ClientNonce + " server,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    [InlineData("r=" + ClientNonce + ",server,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")]
    public async Task ScramBounds_rejects_invalid_server_nonce(string message)
    {
        await AssertRejectedAsync(Encoding.UTF8.GetBytes(message));
    }

    [Fact]
    public async Task ScramBounds_accepts_256_byte_server_nonce_and_rejects_257_bytes()
    {
        string maximumNonce = ClientNonce + new string('a', 256 - ClientNonce.Length);
        SaslScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            ServerFirst(nonce: maximumNonce), TestContext.Current.CancellationToken);

        AssertClientFinal(response, maximumNonce);
        await AssertRejectedAsync(ServerFirst(nonce: maximumNonce + "a"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(4095)]
    [InlineData(1_000_001)]
    public async Task ScramBounds_rejects_iterations_outside_allowed_range(int iterations)
    {
        await AssertRejectedAsync(ServerFirst(iterations: iterations));
    }

    [Fact]
    public async Task ScramBounds_rejects_overflowing_iterations()
    {
        await AssertRejectedAsync(ServerFirst(iterations: "2147483648"));
    }

    [Theory]
    [InlineData(4096)]
    [InlineData(1_000_000)]
    public async Task ScramBounds_accepts_iteration_boundaries(int iterations)
    {
        SaslScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            ServerFirst(iterations: iterations), TestContext.Current.CancellationToken);

        AssertClientFinal(response, ServerNonce);
    }

    [Theory]
    [InlineData("")]
    [InlineData("YQ")]
    [InlineData("YQ== ")]
    [InlineData("A===")]
    [InlineData("AB==")]
    public async Task ScramBounds_rejects_empty_invalid_or_noncanonical_salt(string salt)
    {
        await AssertRejectedAsync(ServerFirst(salt: salt));
    }

    [Fact]
    public async Task ScramBounds_accepts_1024_byte_salt_and_rejects_1025_bytes()
    {
        SaslScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();
        string maximumSalt = Convert.ToBase64String(new byte[1024]);

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            ServerFirst(salt: maximumSalt), TestContext.Current.CancellationToken);

        AssertClientFinal(response, ServerNonce);
        await AssertRejectedAsync(ServerFirst(salt: Convert.ToBase64String(new byte[1025])));
    }

    [Fact]
    public async Task ScramBounds_accepts_16384_byte_message_and_rejects_larger_or_empty_messages()
    {
        byte[] prefix = ServerFirst(extension: "x=");
        byte[] maximumMessage = [.. prefix, .. Enumerable.Repeat((byte)'a', 16_384 - prefix.Length)];
        SaslScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            maximumMessage, TestContext.Current.CancellationToken);

        AssertClientFinal(response, ServerNonce);
        await AssertRejectedAsync([]);
        await AssertRejectedAsync([.. maximumMessage, (byte)'a']);
    }

    [Fact]
    public async Task ScramServerFirst_rejects_invalid_utf8_without_exposing_input()
    {
        await AssertRejectedAsync([0xff, 0xfe, 0xfd]);
    }

    [Fact]
    public async Task ScramServerFirst_accepts_and_proof_binds_exact_utf8_extension()
    {
        const string serverFirst =
            "r=" + ServerNonce + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=é";
        var authenticator = new SaslScramSha256Authenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => ClientNonce);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(
            Encoding.UTF8.GetBytes(serverFirst), TestContext.Current.CancellationToken);

        AssertClientFinal(response, ServerNonce);
    }

    [Fact]
    public async Task ScramServerFinal_accepts_signature_with_optional_extensions()
    {
        SaslScramSha256Authenticator authenticator =
            await CreateProofSentAuthenticatorAsync();

        await authenticator.CompleteAsync(
            "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=,x=extension,y=é"u8.ToArray(),
            TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("x=extension")]
    [InlineData("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=,v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")]
    [InlineData("v=not-base64")]
    [InlineData("v=AB==")]
    [InlineData("v=YQ==")]
    [InlineData("e=server-private-error")]
    public async Task ScramServerFinal_rejects_wrong_missing_duplicate_malformed_or_error(
        string message)
    {
        SaslScramSha256Authenticator authenticator =
            await CreateProofSentAuthenticatorAsync();

        SaslAuthenticationException exception =
            await Assert.ThrowsAsync<SaslAuthenticationException>(
                () => authenticator.CompleteAsync(
                    Encoding.UTF8.GetBytes(message),
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(AuthenticationFailure, exception.Message);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain(message, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScramServerFinal_rejects_empty_completion_before_final_challenge()
    {
        SaslScramSha256Authenticator authenticator =
            await CreateProofSentAuthenticatorAsync();

        SaslAuthenticationException exception =
            await Assert.ThrowsAsync<SaslAuthenticationException>(
                () => authenticator.CompleteAsync(
                    null, TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(AuthenticationFailure, exception.Message);
        Assert.Null(exception.InnerException);
    }

    [Theory]
    [InlineData('p')]
    [InlineData('r')]
    [InlineData('s')]
    [InlineData('i')]
    [InlineData('c')]
    [InlineData('n')]
    [InlineData('a')]
    [InlineData('e')]
    [InlineData('m')]
    [InlineData('v')]
    public async Task ScramServerFinal_rejects_reserved_attribute_as_extension(char name)
    {
        SaslScramSha256Authenticator authenticator =
            await CreateProofSentAuthenticatorAsync();

        SaslAuthenticationException exception =
            await Assert.ThrowsAsync<SaslAuthenticationException>(
                () => authenticator.CompleteAsync(
                    Encoding.UTF8.GetBytes(
                        $"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=,{name}=x"),
                    TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(AuthenticationFailure, exception.Message);
    }

    [Fact]
    public async Task ScramState_duplicate_initial_response_poisons_exchange()
    {
        SaslScramSha256Authenticator authenticator =
            await CreateStartedAuthenticatorAsync();

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.GetInitialResponseAsync(
                TestContext.Current.CancellationToken).AsTask());

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.RespondAsync(
                ServerFirst(), TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task ScramState_extra_challenge_poisons_pending_completion()
    {
        SaslScramSha256Authenticator authenticator =
            await CreateProofSentAuthenticatorAsync();
        await authenticator.RespondAsync(
            "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="u8.ToArray(),
            TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.RespondAsync(
                "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="u8.ToArray(),
                TestContext.Current.CancellationToken).AsTask());

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.CompleteAsync(
                null, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task ScramState_premature_completion_poisons_exchange()
    {
        var authenticator = new SaslScramSha256Authenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => ClientNonce);

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.CompleteAsync(
                null, TestContext.Current.CancellationToken).AsTask());

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.GetInitialResponseAsync(
                TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task ScramServerFirst_rejects_a_second_server_first_message()
    {
        SaslScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();
        await authenticator.RespondAsync(
            ServerFirst(), TestContext.Current.CancellationToken);

        SaslAuthenticationException exception =
            await Assert.ThrowsAsync<SaslAuthenticationException>(
                () => authenticator.RespondAsync(
                    ServerFirst(), TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(AuthenticationFailure, exception.Message);
    }

    private static async Task<SaslScramSha256Authenticator> CreateStartedAuthenticatorAsync()
    {
        var authenticator = new SaslScramSha256Authenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => ClientNonce);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        return authenticator;
    }

    private static async Task<SaslScramSha256Authenticator> CreateProofSentAuthenticatorAsync()
    {
        const string serverNonce =
            ClientNonce + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        SaslScramSha256Authenticator authenticator =
            await CreateStartedAuthenticatorAsync();
        await authenticator.RespondAsync(
            ServerFirst(nonce: serverNonce), TestContext.Current.CancellationToken);
        return authenticator;
    }

    private static async Task<ScramSha256Exchange> CreateProofSentExchangeAsync()
    {
        var exchange = new ScramSha256Exchange(
            "user", "pencil", authorizationIdentity: null, ClientNonce);
        await exchange.GetInitialResponseAsync(TestContext.Current.CancellationToken);
        await exchange.RespondAsync(
            Encoding.UTF8.GetBytes(RfcServerFirst), TestContext.Current.CancellationToken);
        return exchange;
    }

    private static byte[] ServerFirst(
        string salt = "W22ZaJ0SNY7soEsUEjb6gQ==",
        int iterations = 4096,
        string? extension = null,
        string nonce = ServerNonce) =>
        ServerFirst(salt, iterations.ToString(System.Globalization.CultureInfo.InvariantCulture), extension, nonce);

    private static byte[] ServerFirst(string iterations) =>
        ServerFirst("W22ZaJ0SNY7soEsUEjb6gQ==", iterations, extension: null, ServerNonce);

    private static byte[] ServerFirst(
        string salt, string iterations, string? extension, string nonce) =>
        Encoding.UTF8.GetBytes(
            $"r={nonce},s={salt},i={iterations}{(extension is null ? string.Empty : $",{extension}")}");

    private static async Task AssertRejectedAsync(byte[] message)
    {
        SaslScramSha256Authenticator authenticator = await CreateStartedAuthenticatorAsync();

        SaslAuthenticationException exception =
            await Assert.ThrowsAsync<SaslAuthenticationException>(
                () => authenticator.RespondAsync(
                    message, TestContext.Current.CancellationToken).AsTask());

        Assert.Equal(AuthenticationFailure, exception.Message);
        Assert.Null(exception.InnerException);
        if (message.Length > 0)
        {
            Assert.DoesNotContain(
                Encoding.UTF8.GetString(message), exception.ToString(), StringComparison.Ordinal);
        }
    }

    private static void AssertClientFinal(ReadOnlyMemory<byte> response, string nonce)
    {
        string value = Encoding.UTF8.GetString(response.Span);
        string prefix = $"c=biws,r={nonce},p=";
        Assert.StartsWith(prefix, value, StringComparison.Ordinal);
        Assert.Equal(32, Convert.FromBase64String(value[prefix.Length..]).Length);
    }

    private static byte[] AuthenticationResponses(string outcome) =>
        Encoding.ASCII.GetBytes(
            "\"SASL\" \"SCRAM-SHA-256\"\r\nOK\r\n" + outcome);

}
