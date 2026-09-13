using System.Text;
using Transiever.SaslClient;

namespace Transiever.SaslClient.UnitTest;

public sealed class ScramPlusAuthenticatorTests
{
    private const string ClientNonce = "rOprNGfwEbeRWgbNEkqO";
    private const string ServerFirst = "r=" + ClientNonce + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    private static readonly byte[] EndpointBinding =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    [Fact]
    public async Task Channel_binding_is_required_and_is_encoded_in_the_initial_message()
    {
        var authenticator = new SaslScramSha256PlusAuthenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => "nonce");
        var channelBinding = Assert.IsAssignableFrom<ISaslChannelBindingMechanism>(authenticator);

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken).AsTask());

        authenticator = new SaslScramSha256PlusAuthenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => "nonce");
        channelBinding = Assert.IsAssignableFrom<ISaslChannelBindingMechanism>(authenticator);
        Assert.Equal("tls-server-end-point", channelBinding.ChannelBindingName);
        channelBinding.SetChannelBinding("binding"u8.ToArray());
        ReadOnlyMemory<byte> initial = (await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken))!.Value;

        Assert.Equal("p=tls-server-end-point,,n=user,r=nonce"u8.ToArray(), initial.ToArray());
        Assert.Equal("SCRAM-SHA-256-PLUS", authenticator.Mechanism);
    }

    [Fact]
    public async Task Empty_or_repeated_channel_binding_fails_closed()
    {
        var authenticator = new SaslScramSha256PlusAuthenticator(
            "user", "pencil", authorizationIdentity: null, nonceFactory: () => "nonce");
        var channelBinding = Assert.IsAssignableFrom<ISaslChannelBindingMechanism>(authenticator);

        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => Task.Run(
                () => channelBinding.SetChannelBinding(ReadOnlyMemory<byte>.Empty),
                TestContext.Current.CancellationToken));
        channelBinding.SetChannelBinding("binding"u8.ToArray());
        await Assert.ThrowsAsync<SaslAuthenticationException>(
            () => Task.Run(
                () => channelBinding.SetChannelBinding("again"u8.ToArray()),
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Proof_uses_copied_binding_and_escaped_authorization_identity()
    {
        var authenticator = new SaslScramSha256PlusAuthenticator(
            "user", "pencil", "auth=z,id", () => ClientNonce);
        var channelBinding = Assert.IsAssignableFrom<ISaslChannelBindingMechanism>(authenticator);
        byte[] binding = EndpointBinding.ToArray();
        channelBinding.SetChannelBinding(binding);
        Array.Clear(binding);
        await authenticator.GetInitialResponseAsync(TestContext.Current.CancellationToken);

        ReadOnlyMemory<byte> response = await authenticator.RespondAsync(Encoding.UTF8.GetBytes(ServerFirst), TestContext.Current.CancellationToken);

        Assert.Equal(
            "c=cD10bHMtc2VydmVyLWVuZC1wb2ludCxhPWF1dGg9M0R6PTJDaWQsABEiM0RVZneImaq7zN3u/w==,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=BBA0e81cyx7GsKJW4dRhCvKNltHFsz7b/3mV1FaFuC8="u8.ToArray(),
            response.ToArray());
    }

}
