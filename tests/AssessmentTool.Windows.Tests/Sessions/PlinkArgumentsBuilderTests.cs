using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Processes;
using AssessmentTool.Windows.Sessions;
using Xunit;

namespace AssessmentTool.Windows.Tests.Sessions;

public sealed class PlinkArgumentsBuilderTests
{
    private const string Algorithm = "ssh-ed25519";
    private const string Fingerprint = "ssh-ed25519 255 SHA256:fixture";
    private const string PasswordFilePath = @"C:\Assessment Tool\凭据\password.txt";
    private const string PrivateKeyPath = @"D:\客户资料\密钥 文件\audit-key.ppk";

    [Fact]
    public void Password_profile_builds_exact_tokens_without_raw_password_argument()
    {
        var profile = CreateProfile(ConfirmedTrust(), SshAuthenticationMethod.Password);
        var request = new PlinkArgumentsBuildRequest(profile, PasswordFilePath, null);

        var tokens = new PlinkArgumentsBuilder().Build(request).ArgumentTokens;

        Assert.Equal(
            new[]
            {
                "-ssh",
                "-batch",
                "-no-antispoof",
                "-P",
                "22",
                "-l",
                "audit-user",
                "-hostkey",
                Fingerprint,
                "-pwfile",
                PasswordFilePath,
                "router.example.test"
            },
            tokens);
        Assert.DoesNotContain("-pw", tokens);
        Assert.DoesNotContain("S3cret!", tokens);
    }

    [Fact]
    public void Verified_host_key_is_allowed()
    {
        var verified = HostKeyTrustServices.CreateCoordinator().RecordMatchingObservation(
            ConfirmedTrust(),
            new DateTimeOffset(2026, 7, 16, 8, 2, 0, TimeSpan.Zero));
        var request = new PlinkArgumentsBuildRequest(
            CreateProfile(verified, SshAuthenticationMethod.Password),
            PasswordFilePath,
            null);

        var tokens = new PlinkArgumentsBuilder().Build(request).ArgumentTokens;

        Assert.Equal(Fingerprint, tokens[8]);
    }

    [Theory]
    [InlineData(HostKeyTrustState.Unconfigured)]
    [InlineData(HostKeyTrustState.AwaitingProbe)]
    [InlineData(HostKeyTrustState.AwaitingConfirmation)]
    [InlineData(HostKeyTrustState.MismatchBlocked)]
    public void Untrusted_host_key_states_block_batch_connection(HostKeyTrustState state)
    {
        var request = new PlinkArgumentsBuildRequest(
            CreateProfile(TrustInState(state), SshAuthenticationMethod.Password),
            PasswordFilePath,
            null);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            new PlinkArgumentsBuilder().Build(request));

        Assert.Contains("主机指纹", exception.Message);
    }

    [Fact]
    public void Ssh_profile_without_options_is_rejected()
    {
        var profile = new ConnectionProfile("旧设备", "router.example.test", 22, ConnectionProtocol.Ssh);
        var request = new PlinkArgumentsBuildRequest(profile, PasswordFilePath, null);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            new PlinkArgumentsBuilder().Build(request));

        Assert.Contains("SSH 连接配置", exception.Message);
    }

    [Fact]
    public void Non_ssh_profile_is_rejected()
    {
        var profile = new ConnectionProfile("Windows 主机", "server.example.test", 5985, ConnectionProtocol.WinRm);
        var request = new PlinkArgumentsBuildRequest(profile, PasswordFilePath, null);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            new PlinkArgumentsBuilder().Build(request));

        Assert.Contains("仅支持 SSH", exception.Message);
    }

    [Fact]
    public void Ipv6_host_remains_the_final_single_token()
    {
        var endpoint = new SshEndpointIdentity("2001:db8::25", 2222);
        var profile = CreateProfile(
            ConfirmedTrust(endpoint),
            SshAuthenticationMethod.Password,
            host: "2001:db8::25",
            port: 2222);
        var request = new PlinkArgumentsBuildRequest(profile, PasswordFilePath, null);

        var tokens = new PlinkArgumentsBuilder().Build(request).ArgumentTokens;

        Assert.Equal("2222", tokens[4]);
        Assert.Equal("2001:db8::25", tokens.Last());
    }

    [Fact]
    public void Private_key_profile_uses_only_private_key_path_for_authentication()
    {
        var profile = CreateProfile(ConfirmedTrust(), SshAuthenticationMethod.PrivateKey);
        var request = new PlinkArgumentsBuildRequest(profile, null, PrivateKeyPath);

        var tokens = new PlinkArgumentsBuilder().Build(request).ArgumentTokens;

        Assert.Equal("-i", tokens[9]);
        Assert.Equal(PrivateKeyPath, tokens[10]);
        Assert.DoesNotContain("-pw", tokens);
        Assert.DoesNotContain("-pwfile", tokens);
        Assert.DoesNotContain(profile.SshOptions!.CredentialReference.ToString(), tokens);
        Assert.Equal(profile.Host, tokens.Last());
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData(PasswordFilePath, PrivateKeyPath)]
    [InlineData(null, PrivateKeyPath)]
    public void Password_profile_rejects_missing_or_unexpected_credential_paths(
        string? passwordFilePath,
        string? privateKeyPath)
    {
        var request = new PlinkArgumentsBuildRequest(
            CreateProfile(ConfirmedTrust(), SshAuthenticationMethod.Password),
            passwordFilePath,
            privateKeyPath);

        Assert.Throws<ArgumentException>(() => new PlinkArgumentsBuilder().Build(request));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData(PasswordFilePath, PrivateKeyPath)]
    [InlineData(PasswordFilePath, null)]
    public void Private_key_profile_rejects_missing_or_unexpected_credential_paths(
        string? passwordFilePath,
        string? privateKeyPath)
    {
        var request = new PlinkArgumentsBuildRequest(
            CreateProfile(ConfirmedTrust(), SshAuthenticationMethod.PrivateKey),
            passwordFilePath,
            privateKeyPath);

        Assert.Throws<ArgumentException>(() => new PlinkArgumentsBuilder().Build(request));
    }

    [Theory]
    [InlineData(@"password.txt")]
    [InlineData(@"C:password.txt")]
    [InlineData(@"\\server\share\password.txt")]
    [InlineData(@"\\?\C:\secure\password.txt")]
    [InlineData(@"\\.\C:\secure\password.txt")]
    [InlineData(@"C:\secure\password.txt:payload")]
    [InlineData(@"C:\secure\..\password.txt")]
    [InlineData(@"C:\secure\.\password.txt")]
    [InlineData(@"C:\secure\\password.txt")]
    [InlineData(@"C:/secure/password.txt")]
    [InlineData("C:\\secure\\password.txt\n-proxycmd")]
    [InlineData("C:\\secure\\\" -proxycmd evil \"")]
    [InlineData("C:\\secure\\' -proxycmd evil")]
    [InlineData(@"C:\secure\password.txt.")]
    [InlineData("C:\\secure\\password.txt ")]
    [InlineData(@"C:\secure\pass|word.txt")]
    [InlineData(@"C:\secure\CON")]
    [InlineData(@"C:\secure\COM1.txt")]
    public void Unsafe_or_noncanonical_password_paths_are_rejected(string path)
    {
        var request = new PlinkArgumentsBuildRequest(
            CreateProfile(ConfirmedTrust(), SshAuthenticationMethod.Password),
            path,
            null);

        Assert.Throws<ArgumentException>(() => new PlinkArgumentsBuilder().Build(request));
    }

    [Theory]
    [InlineData(@"D:\密钥\key.ppk:stream")]
    [InlineData(@"\??\D:\密钥\key.ppk")]
    [InlineData("D:\\密钥\\key.ppk\0-i")]
    public void Unsafe_private_key_paths_are_rejected(string path)
    {
        var request = new PlinkArgumentsBuildRequest(
            CreateProfile(ConfirmedTrust(), SshAuthenticationMethod.PrivateKey),
            null,
            path);

        Assert.Throws<ArgumentException>(() => new PlinkArgumentsBuilder().Build(request));
    }

    [Fact]
    public void Jump_host_is_rejected_instead_of_being_ignored_or_mapped_to_proxycmd()
    {
        var profile = CreateProfileWithJumpHost();
        var request = new PlinkArgumentsBuildRequest(profile, PasswordFilePath, null);

        var exception = Assert.Throws<NotSupportedException>(() =>
            new PlinkArgumentsBuilder().Build(request));

        Assert.Contains("当前版本未启用经验证跳板机", exception.Message);
        Assert.DoesNotContain("proxycmd", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("Host", "-host")]
    [InlineData("Host", "host name")]
    [InlineData("UserName", "-user")]
    [InlineData("UserName", "user name")]
    public void Builder_fails_closed_if_core_host_or_username_invariants_are_bypassed(
        string propertyName,
        string invalidValue)
    {
        var profile = CreateProfile(ConfirmedTrust(), SshAuthenticationMethod.Password);
        var target = propertyName == "Host" ? (object)profile : profile.SshOptions!;
        SetAutoProperty(target, propertyName, invalidValue);
        var request = new PlinkArgumentsBuildRequest(profile, PasswordFilePath, null);

        Assert.Throws<ArgumentException>(() => new PlinkArgumentsBuilder().Build(request));
    }

    [Theory]
    [InlineData("Host", "router-b.example.test")]
    [InlineData("Port", 2222)]
    public void Builder_rejects_valid_profile_endpoint_replacement_after_core_validation(
        string propertyName,
        object replacement)
    {
        var profile = CreateProfile(ConfirmedTrust(), SshAuthenticationMethod.Password);
        SetAutoProperty(profile, propertyName, replacement);
        var request = new PlinkArgumentsBuildRequest(profile, PasswordFilePath, null);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            new PlinkArgumentsBuilder().Build(request));

        Assert.Contains("端点", exception.Message);
    }

    [Fact]
    public void Builder_exposes_only_internal_token_api_and_no_raw_execute_or_argument_string_api()
    {
        Assert.False(typeof(PlinkArgumentsBuilder).IsPublic);
        Assert.False(typeof(PlinkArgumentsBuildRequest).IsPublic);

        var declaredMethods = typeof(PlinkArgumentsBuilder).GetMethods(
            BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
        var build = Assert.Single(declaredMethods, method => method.Name == "Build");

        Assert.False(build.IsPublic);
        Assert.Equal(typeof(PlinkArgumentsBuilder.LaunchPlan), build.ReturnType);
        Assert.True(typeof(ProcessArgumentPlan).IsAssignableFrom(build.ReturnType));
        var constructor = Assert.Single(build.ReturnType.GetConstructors(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic));
        Assert.True(constructor.IsPrivate);
        Assert.DoesNotContain(declaredMethods, method =>
            method.IsPublic && method.ReturnType == typeof(string));
        Assert.DoesNotContain(declaredMethods, method =>
            method.Name.IndexOf("Execute", StringComparison.OrdinalIgnoreCase) >= 0);
        Assert.DoesNotContain(build.GetParameters(), parameter =>
            parameter.ParameterType == typeof(string));
    }

    [Fact]
    public void Lexical_path_validation_does_not_claim_to_return_a_canonical_path()
    {
        var declaredMethods = typeof(PlinkArgumentsBuilder).GetMethods(
            BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);

        Assert.DoesNotContain(declaredMethods, method =>
            method.Name.IndexOf("Canonical", StringComparison.OrdinalIgnoreCase) >= 0);
    }

    private static ConnectionProfile CreateProfile(
        HostKeyTrust trust,
        SshAuthenticationMethod authenticationMethod,
        string host = "router.example.test",
        int port = 22)
    {
        var privateKeyReference = authenticationMethod == SshAuthenticationMethod.PrivateKey
            ? PrivateKeyReference.New()
            : (PrivateKeyReference?)null;
        var options = new SshConnectionOptions(
            "audit-user",
            authenticationMethod,
            CredentialReference.New(),
            privateKeyReference,
            trust);

        return new ConnectionProfile("核心交换机", host, port, ConnectionProtocol.Ssh, options);
    }

    private static ConnectionProfile CreateProfileWithJumpHost()
    {
        var jumpHost = new SshHop(
            "jump.example.test",
            22,
            "jump-auditor",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            ConfirmedTrust(new SshEndpointIdentity("jump.example.test", 22)));
        var options = new SshConnectionOptions(
            "audit-user",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            ConfirmedTrust(),
            jumpHost);

        return new ConnectionProfile(
            "经跳板机设备",
            "router.example.test",
            22,
            ConnectionProtocol.Ssh,
            options);
    }

    private static HostKeyTrust ConfirmedTrust()
    {
        return ConfirmedTrust(new SshEndpointIdentity("router.example.test", 22));
    }

    private static HostKeyTrust ConfirmedTrust(SshEndpointIdentity endpoint)
    {
        var observedAt = new DateTimeOffset(2026, 7, 16, 8, 0, 0, TimeSpan.Zero);
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var probing = coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint));
        var awaiting = coordinator.RecordObservation(probing, Algorithm, Fingerprint, observedAt);
        return coordinator.Confirm(
            awaiting,
            observedAt.AddMinutes(1),
            "设备控制台核对");
    }

    private static HostKeyTrust TrustInState(HostKeyTrustState state)
    {
        switch (state)
        {
            case HostKeyTrustState.Unconfigured:
                return HostKeyTrust.Unconfigured(new SshEndpointIdentity("router.example.test", 22));
            case HostKeyTrustState.AwaitingProbe:
                return HostKeyTrustServices.CreateCoordinator().BeginProbe(
                    HostKeyTrust.Unconfigured(new SshEndpointIdentity("router.example.test", 22)));
            case HostKeyTrustState.AwaitingConfirmation:
                var coordinator = HostKeyTrustServices.CreateCoordinator();
                var probing = coordinator.BeginProbe(HostKeyTrust.Unconfigured(
                    new SshEndpointIdentity("router.example.test", 22)));
                return coordinator.RecordObservation(
                    probing,
                    Algorithm,
                    Fingerprint,
                    new DateTimeOffset(2026, 7, 16, 8, 0, 0, TimeSpan.Zero));
            case HostKeyTrustState.MismatchBlocked:
                return HostKeyTrustServices.CreateCoordinator().RecordMismatchObservation(
                    ConfirmedTrust(),
                    "ssh-rsa",
                    "ssh-rsa 3072 SHA256:different",
                    new DateTimeOffset(2026, 7, 16, 8, 2, 0, TimeSpan.Zero));
            default:
                throw new ArgumentOutOfRangeException(nameof(state), state, null);
        }
    }

    private static void SetAutoProperty(object target, string propertyName, object value)
    {
        var field = target.GetType().GetField(
            "<" + propertyName + ">k__BackingField",
            BindingFlags.Instance | BindingFlags.NonPublic);

        Assert.NotNull(field);
        field!.SetValue(target, value);
    }
}
