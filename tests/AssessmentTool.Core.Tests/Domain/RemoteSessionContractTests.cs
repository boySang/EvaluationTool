using System;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Domain;

public sealed class RemoteSessionContractTests
{
    private const string Algorithm = "ssh-ed25519";
    private const string Fingerprint = "ssh-ed25519 255 SHA256:fixture";

    [Fact]
    public void Ssh_endpoint_identity_normalizes_dns_ipv4_and_ipv6_values()
    {
        var dns = new SshEndpointIdentity("Router.Example.COM.", 22);
        var ipv4 = new SshEndpointIdentity("192.0.2.10", 2222);
        var ipv6 = new SshEndpointIdentity("2001:0DB8:0:0:0:0:0:10", 22);

        Assert.Equal("router.example.com", dns.Host);
        Assert.Equal(new SshEndpointIdentity("192.0.2.10", 2222), ipv4);
        Assert.Equal(new SshEndpointIdentity("2001:db8::10", 22), ipv6);
        Assert.Equal(ConnectionProtocol.Ssh, dns.Protocol);
    }

    [Fact]
    public void Ssh_endpoint_identity_treats_dns_case_and_trailing_dot_as_equal_but_not_ports()
    {
        var canonical = new SshEndpointIdentity("router.example.com", 22);
        var equivalent = new SshEndpointIdentity("Router.Example.COM.", 22);
        var anotherPort = new SshEndpointIdentity("router.example.com", 2222);

        Assert.Equal(canonical, equivalent);
        Assert.Equal(canonical.GetHashCode(), equivalent.GetHashCode());
        Assert.NotEqual(canonical, anotherPort);
    }

    [Fact]
    public void Host_key_trust_is_immutably_bound_to_one_normalized_endpoint()
    {
        var endpoint = new SshEndpointIdentity("Router.Example.COM.", 22);

        var trust = HostKeyTrust.Unconfigured(endpoint);

        Assert.Equal(new SshEndpointIdentity("router.example.com", 22), trust.Endpoint);
        Assert.False(typeof(HostKeyTrust).GetProperty(nameof(HostKeyTrust.Endpoint))!.CanWrite);
    }

    [Fact]
    public void Legacy_ssh_profile_without_options_cannot_connect_automatically()
    {
        var profile = new ConnectionProfile("交换机A", "192.0.2.10", 22, ConnectionProtocol.Ssh);

        Assert.Null(profile.SshOptions);
        Assert.False(profile.IsEligibleForAutomaticConnection);
    }

    [Fact]
    public void Ssh_profile_uses_one_immutable_host_key_trust_source()
    {
        var profile = CreateSshProfile(ConfirmedTrust());

        Assert.NotNull(profile.SshOptions);
        Assert.Same(profile.SshOptions!.HostKeyTrust, profile.SshOptions.HostKeyTrust);
        Assert.Null(typeof(ConnectionProfile).GetProperty("PinnedHostKey"));
        Assert.All(typeof(SshConnectionOptions).GetProperties(), property => Assert.False(property.CanWrite));
    }

    [Fact]
    public void Ssh_options_reject_host_key_trust_for_another_endpoint()
    {
        var optionsEndpoint = new SshEndpointIdentity("router-a.example.com", 22);
        var trust = HostKeyTrust.Unconfigured(new SshEndpointIdentity("router-b.example.com", 22));

        Assert.Throws<ArgumentException>(() => new SshConnectionOptions(
            optionsEndpoint,
            "audit-user",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            trust));
    }

    [Fact]
    public void Connection_profile_rejects_ssh_options_for_another_endpoint()
    {
        var endpoint = new SshEndpointIdentity("router-a.example.com", 22);
        var options = PasswordOptions(endpoint, ConfirmedTrust(endpoint));

        Assert.Throws<ArgumentException>(() => new ConnectionProfile(
            "交换机A",
            "router-b.example.com",
            22,
            ConnectionProtocol.Ssh,
            options));
    }

    [Fact]
    public void Non_ssh_profile_rejects_ssh_options()
    {
        var options = PasswordOptions(TargetEndpoint(), ConfirmedTrust());

        var exception = Assert.Throws<ArgumentException>(() =>
            new ConnectionProfile("服务器A", "server.example.com", 5985, ConnectionProtocol.WinRm, options));

        Assert.Contains("仅 SSH", exception.Message);
    }

    [Theory]
    [InlineData(HostKeyTrustState.Unconfigured, false)]
    [InlineData(HostKeyTrustState.AwaitingProbe, false)]
    [InlineData(HostKeyTrustState.AwaitingConfirmation, false)]
    [InlineData(HostKeyTrustState.Pinned, true)]
    [InlineData(HostKeyTrustState.Verified, true)]
    [InlineData(HostKeyTrustState.MismatchBlocked, false)]
    public void Automatic_connection_allows_only_pinned_or_verified_trust(
        HostKeyTrustState state,
        bool expected)
    {
        var profile = CreateSshProfile(TrustInState(state));

        Assert.Equal(expected, profile.IsEligibleForAutomaticConnection);
    }

    [Fact]
    public void Password_authentication_uses_strong_credential_reference_without_private_key()
    {
        var credentialReference = CredentialReference.New();
        var options = new SshConnectionOptions(
            TargetEndpoint(),
            "audit-user",
            SshAuthenticationMethod.Password,
            credentialReference,
            null,
            ConfirmedTrust());

        Assert.Equal(credentialReference, options.CredentialReference);
        Assert.Null(options.PrivateKeyReference);
        Assert.NotEqual(typeof(string), typeof(SshConnectionOptions).GetProperty("CredentialReference")!.PropertyType);
        Assert.NotEqual(typeof(string), typeof(SshConnectionOptions).GetProperty("PrivateKeyReference")!.PropertyType);
    }

    [Fact]
    public void Private_key_authentication_requires_opaque_references_not_paths_or_content()
    {
        var credentialReference = CredentialReference.New();
        var privateKeyReference = PrivateKeyReference.New();
        var options = new SshConnectionOptions(
            TargetEndpoint(),
            "audit-user",
            SshAuthenticationMethod.PrivateKey,
            credentialReference,
            privateKeyReference,
            ConfirmedTrust());

        Assert.Equal(privateKeyReference, options.PrivateKeyReference);
        Assert.Throws<ArgumentException>(() => PrivateKeyReference.Parse(@"C:\keys\id.ppk"));
        Assert.Throws<ArgumentException>(() => PrivateKeyReference.Parse("-----BEGIN PRIVATE KEY-----"));
    }

    [Fact]
    public void Authentication_method_and_private_key_reference_must_agree()
    {
        Assert.Throws<ArgumentException>(() => new SshConnectionOptions(
            TargetEndpoint(),
            "audit-user",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            PrivateKeyReference.New(),
            ConfirmedTrust()));

        Assert.Throws<ArgumentException>(() => new SshConnectionOptions(
            TargetEndpoint(),
            "audit-user",
            SshAuthenticationMethod.PrivateKey,
            CredentialReference.New(),
            null,
            ConfirmedTrust()));
    }

    [Fact]
    public void Null_host_key_trust_error_uses_chinese_user_text()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => new SshConnectionOptions(
            TargetEndpoint(),
            "audit-user",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            null!));

        Assert.Contains("主机指纹信任", exception.Message);
    }

    [Fact]
    public void Host_key_confirmation_preserves_algorithm_fingerprint_times_and_source()
    {
        var observedAt = new DateTimeOffset(2026, 7, 16, 8, 0, 0, TimeSpan.Zero);
        var confirmedAt = observedAt.AddMinutes(3);

        var endpoint = TargetEndpoint();
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var probing = coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint));
        var awaiting = coordinator.RecordObservation(probing, Algorithm, Fingerprint, observedAt);
        var trust = coordinator
            .Confirm(awaiting, confirmedAt, "设备控制台核对");

        Assert.Equal(HostKeyTrustState.Pinned, trust.State);
        Assert.Equal(endpoint, trust.Endpoint);
        Assert.Equal(Algorithm, trust.Algorithm);
        Assert.Equal(Fingerprint, trust.Fingerprint);
        Assert.Equal(observedAt, trust.ObservedAt);
        Assert.Equal(confirmedAt, trust.ConfirmedAt);
        Assert.Equal("设备控制台核对", trust.ConfirmationSource);
    }

    [Fact]
    public void Public_host_key_value_api_cannot_mint_pinned_trust_directly()
    {
        Assert.Empty(typeof(HostKeyTrust).GetConstructors());
        Assert.Null(typeof(HostKeyTrust).GetMethod(
            "Confirm",
            BindingFlags.Instance | BindingFlags.Public));
        Assert.Null(typeof(HostKeyTrust).GetMethod(
            "AwaitingConfirmation",
            BindingFlags.Static | BindingFlags.Public));
        Assert.Null(typeof(HostKeyTrust).GetMethod(
            "RecordObservation",
            BindingFlags.Instance | BindingFlags.Public));
        Assert.True(typeof(HostKeyTrustServices).IsPublic);
        Assert.NotNull(typeof(HostKeyTrustServices).GetMethod(
            nameof(HostKeyTrustServices.CreateCoordinator),
            BindingFlags.Static | BindingFlags.Public));
        Assert.True(typeof(HostKeyTrustCoordinator).IsPublic);
        Assert.True(typeof(HostKeyTrustCoordinator).IsSealed);
        Assert.Empty(typeof(HostKeyTrustCoordinator).GetConstructors());
        Assert.Null(typeof(HostKeyTrust).Assembly.GetType(
            "AssessmentTool.Core.Domain.IHostKeyConfirmationService"));
    }

    [Fact]
    public void Probe_must_record_an_observation_before_confirmation_is_possible()
    {
        var endpoint = TargetEndpoint();

        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var probing = coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint));
        var awaiting = coordinator.RecordObservation(
            probing,
            Algorithm,
            Fingerprint,
            DateTimeOffset.UtcNow);

        Assert.Equal(HostKeyTrustState.AwaitingProbe, probing.State);
        Assert.Equal(HostKeyTrustState.AwaitingConfirmation, awaiting.State);
        Assert.Equal(endpoint, awaiting.Endpoint);
    }

    [Fact]
    public void Verified_trust_remains_eligible_and_records_latest_observation()
    {
        var verifiedAt = DateTimeOffset.UtcNow;

        var trust = HostKeyTrustServices.CreateCoordinator().RecordMatchingObservation(
            ConfirmedTrust(),
            verifiedAt);

        Assert.Equal(HostKeyTrustState.Verified, trust.State);
        Assert.Equal(TargetEndpoint(), trust.Endpoint);
        Assert.Equal(Fingerprint, trust.Fingerprint);
        Assert.Equal(verifiedAt, trust.ObservedAt);
        Assert.True(trust.IsEligibleForAutomaticConnection);
        Assert.Equal(HostKeyTrustAuditEventKind.MatchingVerification, trust.AuditHistory.Last().Kind);
        Assert.Equal(Fingerprint, trust.AuditHistory.Last().Fingerprint);
    }

    [Fact]
    public void Mismatch_blocks_connection_without_overwriting_pinned_fingerprint()
    {
        var pinned = ConfirmedTrust();
        var observedAt = DateTimeOffset.UtcNow;

        var blocked = HostKeyTrustServices.CreateCoordinator().RecordMismatchObservation(
            pinned,
            "ssh-rsa",
            "ssh-rsa 3072 SHA256:different",
            observedAt);

        Assert.Equal(HostKeyTrustState.MismatchBlocked, blocked.State);
        Assert.Equal(Algorithm, blocked.Algorithm);
        Assert.Equal(Fingerprint, blocked.Fingerprint);
        Assert.Equal("ssh-rsa", blocked.ObservedAlgorithm);
        Assert.Equal("ssh-rsa 3072 SHA256:different", blocked.ObservedFingerprint);
        Assert.Equal(observedAt, blocked.ObservedAt);
        Assert.False(blocked.IsEligibleForAutomaticConnection);
        Assert.All(typeof(HostKeyTrust).GetProperties(), property => Assert.False(property.CanWrite));
    }

    [Fact]
    public void Mismatch_reconfirmation_uses_service_and_preserves_old_and_new_audit_fields()
    {
        var oldTrust = ConfirmedTrust();
        var mismatchAt = DateTimeOffset.UtcNow;
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var blocked = coordinator.RecordMismatchObservation(
            oldTrust,
            "ssh-rsa",
            "ssh-rsa 3072 SHA256:different",
            mismatchAt);

        var awaiting = coordinator.BeginReconfirmation(blocked);
        var repinned = coordinator.Confirm(
            awaiting,
            mismatchAt.AddMinutes(1),
            "设备变更单核对");

        Assert.Equal(HostKeyTrustState.Pinned, repinned.State);
        Assert.Equal("ssh-rsa", repinned.Algorithm);
        Assert.Equal("ssh-rsa 3072 SHA256:different", repinned.Fingerprint);
        Assert.Equal(Algorithm, repinned.PreviousAlgorithm);
        Assert.Equal(Fingerprint, repinned.PreviousFingerprint);
        Assert.Equal(oldTrust.ConfirmedAt, repinned.PreviousConfirmedAt);
        Assert.Equal(oldTrust.ConfirmationSource, repinned.PreviousConfirmationSource);
        Assert.Equal(TargetEndpoint(), repinned.Endpoint);
    }

    [Fact]
    public void Two_host_key_replacements_preserve_the_complete_immutable_audit_history()
    {
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var firstPin = ConfirmedTrust();
        var firstMismatchAt = firstPin.ConfirmedAt!.Value.AddMinutes(1);
        var firstMismatch = coordinator.RecordMismatchObservation(
            firstPin,
            "ssh-rsa",
            "ssh-rsa 3072 SHA256:first-replacement",
            firstMismatchAt);
        var secondPin = coordinator.Confirm(
            coordinator.BeginReconfirmation(firstMismatch),
            firstMismatchAt.AddMinutes(1),
            "第一次设备变更单核对");
        var secondMismatchAt = firstMismatchAt.AddMinutes(2);
        var secondMismatch = coordinator.RecordMismatchObservation(
            secondPin,
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp256 256 SHA256:second-replacement",
            secondMismatchAt);
        var thirdPin = coordinator.Confirm(
            coordinator.BeginReconfirmation(secondMismatch),
            secondMismatchAt.AddMinutes(1),
            "第二次设备变更单核对");

        Assert.Equal(
            new[]
            {
                HostKeyTrustAuditEventKind.InitialPin,
                HostKeyTrustAuditEventKind.MismatchObserved,
                HostKeyTrustAuditEventKind.Reconfirmed,
                HostKeyTrustAuditEventKind.MismatchObserved,
                HostKeyTrustAuditEventKind.Reconfirmed
            },
            thirdPin.AuditHistory.Select(auditEvent => auditEvent.Kind));
        Assert.All(thirdPin.AuditHistory, auditEvent =>
        {
            Assert.Equal(TargetEndpoint(), auditEvent.Endpoint);
            Assert.Equal(TimeSpan.Zero, auditEvent.OccurredAt.Offset);
            Assert.False(string.IsNullOrWhiteSpace(auditEvent.Algorithm));
            Assert.False(string.IsNullOrWhiteSpace(auditEvent.Fingerprint));
            Assert.False(string.IsNullOrWhiteSpace(auditEvent.Source));
        });
        Assert.Equal(Fingerprint, thirdPin.AuditHistory[0].Fingerprint);
        Assert.Equal("ssh-rsa 3072 SHA256:first-replacement", thirdPin.AuditHistory[2].Fingerprint);
        Assert.Equal("ecdsa-sha2-nistp256 256 SHA256:second-replacement", thirdPin.AuditHistory[4].Fingerprint);
        Assert.False(typeof(HostKeyTrust).GetProperty(nameof(HostKeyTrust.AuditHistory))!.CanWrite);
        Assert.All(typeof(HostKeyTrustAuditEvent).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.Throws<NotSupportedException>(() =>
            ((System.Collections.Generic.IList<HostKeyTrustAuditEvent>)thirdPin.AuditHistory).Add(
                thirdPin.AuditHistory[0]));
    }

    [Fact]
    public void Matching_fingerprint_cannot_be_recorded_as_mismatch()
    {
        var trust = ConfirmedTrust();

        Assert.Throws<ArgumentException>(() =>
            HostKeyTrustServices.CreateCoordinator().RecordMismatchObservation(
                trust,
                Algorithm,
                Fingerprint,
                DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("-target.example.com")]
    [InlineData("target.example.com/path")]
    [InlineData("target.example.com\\path")]
    [InlineData("target.example.com\0evil")]
    [InlineData("target.example.com\rnext")]
    [InlineData("target.example.com\nnext")]
    [InlineData("target.\"example.com")]
    [InlineData("target.'example.com")]
    [InlineData("not a host")]
    [InlineData("host_name.example.com")]
    [InlineData("host١.example.com")]
    public void Connection_profile_rejects_unsafe_or_non_host_values(string host)
    {
        Assert.Throws<ArgumentException>(() =>
            new ConnectionProfile("设备A", host, 22, ConnectionProtocol.Ssh));
    }

    [Fact]
    public void Null_host_error_uses_chinese_user_text()
    {
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new ConnectionProfile("设备A", null!, 22, ConnectionProtocol.Ssh));

        Assert.Contains("主机", exception.Message);
    }

    [Theory]
    [InlineData("Router.Example.COM.", "router.example.com")]
    [InlineData("192.0.2.10", "192.0.2.10")]
    [InlineData("2001:0DB8:0:0:0:0:0:10", "2001:db8::10")]
    public void Connection_profile_normalizes_dns_ipv4_and_ipv6_hosts(string host, string expected)
    {
        var profile = new ConnectionProfile("设备A", host, 22, ConnectionProtocol.Ssh);

        Assert.Equal(expected, profile.Host);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("-audit")]
    [InlineData("audit user")]
    [InlineData("audit/user")]
    [InlineData("audit\\user")]
    [InlineData("audit\0user")]
    [InlineData("audit\ruser")]
    [InlineData("audit\nuser")]
    [InlineData("audit\"user")]
    [InlineData("audit'user")]
    public void Ssh_username_rejects_unsafe_values(string userName)
    {
        Assert.Throws<ArgumentException>(() => new SshConnectionOptions(
            TargetEndpoint(),
            userName,
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            ConfirmedTrust()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("-ssh-ed25519 255 SHA256:fixture")]
    [InlineData("ssh-ed25519 255 SHA256:bad/path")]
    [InlineData("ssh-ed25519 255 SHA256:bad\\path")]
    [InlineData("ssh-ed25519 255 SHA256:bad\0value")]
    [InlineData("ssh-ed25519 255 SHA256:bad\rvalue")]
    [InlineData("ssh-ed25519 255 SHA256:bad\nvalue")]
    [InlineData("ssh-ed25519 255 SHA256:\"bad\"")]
    [InlineData("ssh-ed25519 255 SHA256:'bad'")]
    public void Host_key_fingerprint_rejects_unsafe_values(string fingerprint)
    {
        Assert.Throws<ArgumentException>(() =>
            HostKeyTrustServices.CreateCoordinator().RecordObservation(
                HostKeyTrustServices.CreateCoordinator().BeginProbe(HostKeyTrust.Unconfigured(TargetEndpoint())),
                Algorithm,
                fingerprint,
                DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public void Ssh_jump_host_rejects_ports_outside_tcp_range(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SshHop(
            "jump.example.com",
            port,
            "audit-user",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            ConfirmedTrust(new SshEndpointIdentity("jump.example.com", 22))));
    }

    [Fact]
    public void Jump_host_is_preserved_as_an_immutable_extension()
    {
        var jumpHost = new SshHop(
            "jump.example.com",
            22,
            "jump-audit",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            ConfirmedTrust(new SshEndpointIdentity("jump.example.com", 22)));
        var options = new SshConnectionOptions(
            TargetEndpoint(),
            "audit-user",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            ConfirmedTrust(),
            jumpHost);

        Assert.Same(jumpHost, options.JumpHost);
        Assert.All(typeof(SshHop).GetProperties(), property => Assert.False(property.CanWrite));
    }

    [Fact]
    public void Profile_with_jump_host_is_not_eligible_until_a_verified_adapter_supports_it()
    {
        var jumpHost = new SshHop(
            "jump.example.com",
            22,
            "jump-audit",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            ConfirmedTrust(new SshEndpointIdentity("jump.example.com", 22)));
        var options = new SshConnectionOptions(
            TargetEndpoint(),
            "audit-user",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            ConfirmedTrust(),
            jumpHost);
        var profile = new ConnectionProfile(
            "交换机A",
            "192.0.2.10",
            22,
            ConnectionProtocol.Ssh,
            options);

        Assert.False(profile.IsEligibleForAutomaticConnection);
    }

    [Fact]
    public void Remote_session_has_no_public_string_command_execution_entry()
    {
        var executeMethods = typeof(IRemoteSession)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.Name == "ExecuteAsync")
            .ToArray();

        var method = Assert.Single(executeMethods);
        Assert.Equal(typeof(Task<CommandOutput>), method.ReturnType);
        Assert.Equal(
            new[] { typeof(CommandDefinition), typeof(CancellationToken) },
            method.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        Assert.DoesNotContain(executeMethods, candidate =>
            candidate.GetParameters().Any(parameter => parameter.ParameterType == typeof(string)));
    }

    [Fact]
    public void Command_output_retains_execution_evidence_and_safe_failure_category()
    {
        var startedAt = DateTimeOffset.UtcNow;
        var completedAt = startedAt.AddSeconds(2);
        var output = new CommandOutput(
            "cmd-7a",
            "原始标准输出",
            "原始标准错误",
            1,
            RemoteExecutionOutcome.Failed,
            RemoteFailureCategory.AuthenticationFailed,
            startedAt,
            completedAt);

        Assert.Equal("cmd-7a", output.CommandId);
        Assert.Equal("原始标准输出", output.StandardOutput);
        Assert.Equal("原始标准错误", output.StandardError);
        Assert.Equal(1, output.ExitCode);
        Assert.Equal(RemoteExecutionOutcome.Failed, output.Outcome);
        Assert.Equal(RemoteFailureCategory.AuthenticationFailed, output.FailureCategory);
        Assert.Equal(startedAt, output.StartedAt);
        Assert.Equal(completedAt, output.CompletedAt);
        Assert.Contains("认证", output.UserErrorMessage);
        Assert.DoesNotContain("原始标准错误", output.UserErrorMessage);
    }

    [Fact]
    public void Successful_command_output_cannot_carry_a_failure_category()
    {
        Assert.Throws<ArgumentException>(() => new CommandOutput(
            "cmd-7a",
            "output",
            "",
            0,
            RemoteExecutionOutcome.Succeeded,
            RemoteFailureCategory.ProcessFailed,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Command_output_requires_a_completed_at_terminal_timestamp()
    {
        var constructor = Assert.Single(typeof(CommandOutput).GetConstructors());
        var completedAtParameter = Assert.Single(
            constructor.GetParameters(),
            parameter => parameter.Name == "completedAt");

        Assert.Equal(typeof(DateTimeOffset), completedAtParameter.ParameterType);
        Assert.Equal(typeof(DateTimeOffset), typeof(CommandOutput).GetProperty(nameof(CommandOutput.CompletedAt))!.PropertyType);
    }

    [Fact]
    public void Command_output_rejects_completion_before_start()
    {
        var startedAt = new DateTimeOffset(2026, 7, 16, 16, 0, 0, TimeSpan.FromHours(8));

        Assert.Throws<ArgumentOutOfRangeException>(() => new CommandOutput(
            "cmd-7a",
            "",
            "",
            0,
            RemoteExecutionOutcome.Succeeded,
            null,
            startedAt,
            startedAt.AddTicks(-1)));
    }

    [Fact]
    public void Command_output_normalizes_execution_times_to_utc()
    {
        var startedAt = new DateTimeOffset(2026, 7, 16, 16, 0, 0, TimeSpan.FromHours(8));
        var completedAt = startedAt.AddSeconds(2);

        var output = new CommandOutput(
            "cmd-7a",
            "",
            "",
            0,
            RemoteExecutionOutcome.Succeeded,
            null,
            startedAt,
            completedAt);

        Assert.Equal(startedAt.UtcDateTime, output.StartedAt.UtcDateTime);
        Assert.Equal(completedAt.UtcDateTime, output.CompletedAt.UtcDateTime);
        Assert.Equal(TimeSpan.Zero, output.StartedAt.Offset);
        Assert.Equal(TimeSpan.Zero, output.CompletedAt.Offset);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(1)]
    public void Successful_command_output_requires_zero_exit_code(int? exitCode)
    {
        Assert.Throws<ArgumentException>(() => new CommandOutput(
            "cmd-7a",
            "output",
            "",
            exitCode,
            RemoteExecutionOutcome.Succeeded,
            null,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Successful_command_output_accepts_zero_exit_code_without_failure()
    {
        var output = new CommandOutput(
            "cmd-7a",
            "output",
            "",
            0,
            RemoteExecutionOutcome.Succeeded,
            null,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow);

        Assert.Equal(0, output.ExitCode);
        Assert.Null(output.FailureCategory);
    }

    [Theory]
    [InlineData(RemoteFailureCategory.AuthenticationFailed)]
    [InlineData(RemoteFailureCategory.HostKeyRejected)]
    [InlineData(RemoteFailureCategory.NetworkFailed)]
    [InlineData(RemoteFailureCategory.ProcessFailed)]
    [InlineData(RemoteFailureCategory.UnsafeCommand)]
    public void Stopped_command_output_allows_only_cancelled_or_timed_out(
        RemoteFailureCategory failureCategory)
    {
        Assert.Throws<ArgumentException>(() => new CommandOutput(
            "cmd-7a",
            "",
            "",
            null,
            RemoteExecutionOutcome.Stopped,
            failureCategory,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData(RemoteFailureCategory.Cancelled)]
    [InlineData(RemoteFailureCategory.TimedOut)]
    public void Stopped_command_output_accepts_cancelled_or_timed_out(
        RemoteFailureCategory failureCategory)
    {
        var output = new CommandOutput(
            "cmd-7a",
            "",
            "",
            null,
            RemoteExecutionOutcome.Stopped,
            failureCategory,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow);

        Assert.Equal(failureCategory, output.FailureCategory);
    }

    [Fact]
    public void Stopped_command_output_rejects_zero_exit_code()
    {
        Assert.Throws<ArgumentException>(() => new CommandOutput(
            "cmd-7a",
            "",
            "",
            0,
            RemoteExecutionOutcome.Stopped,
            RemoteFailureCategory.Cancelled,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData(RemoteFailureCategory.Cancelled)]
    [InlineData(RemoteFailureCategory.TimedOut)]
    public void Failed_command_output_rejects_stopped_categories(
        RemoteFailureCategory failureCategory)
    {
        Assert.Throws<ArgumentException>(() => new CommandOutput(
            "cmd-7a",
            "",
            "",
            null,
            RemoteExecutionOutcome.Failed,
            failureCategory,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Failed_command_output_rejects_zero_exit_code()
    {
        Assert.Throws<ArgumentException>(() => new CommandOutput(
            "cmd-7a",
            "",
            "",
            0,
            RemoteExecutionOutcome.Failed,
            RemoteFailureCategory.ProcessFailed,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(1)]
    public void Failed_command_output_accepts_null_or_nonzero_exit_code(int? exitCode)
    {
        var output = new CommandOutput(
            "cmd-7a",
            "",
            "",
            exitCode,
            RemoteExecutionOutcome.Failed,
            RemoteFailureCategory.ProcessFailed,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow);

        Assert.Equal(exitCode, output.ExitCode);
    }

    [Fact]
    public void Null_standard_output_error_uses_chinese_user_text()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => new CommandOutput(
            "cmd-7a",
            null!,
            "",
            null,
            RemoteExecutionOutcome.Failed,
            RemoteFailureCategory.ProcessFailed,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow));

        Assert.Contains("标准输出", exception.Message);
    }

    private static ConnectionProfile CreateSshProfile(HostKeyTrust trust)
    {
        return new ConnectionProfile(
            "交换机A",
            "192.0.2.10",
            22,
            ConnectionProtocol.Ssh,
            PasswordOptions(TargetEndpoint(), trust));
    }

    private static SshConnectionOptions PasswordOptions(
        SshEndpointIdentity endpoint,
        HostKeyTrust trust)
    {
        return new SshConnectionOptions(
            endpoint,
            "audit-user",
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            trust);
    }

    private static HostKeyTrust ConfirmedTrust()
    {
        return ConfirmedTrust(TargetEndpoint());
    }

    private static HostKeyTrust ConfirmedTrust(SshEndpointIdentity endpoint)
    {
        var observedAt = new DateTimeOffset(2026, 7, 16, 8, 0, 0, TimeSpan.Zero);
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var probing = coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint));
        var awaiting = coordinator.RecordObservation(probing, Algorithm, Fingerprint, observedAt);
        return coordinator
            .Confirm(awaiting, observedAt.AddMinutes(1), "设备控制台核对");
    }

    private static SshEndpointIdentity TargetEndpoint()
    {
        return new SshEndpointIdentity("192.0.2.10", 22);
    }

    private static HostKeyTrust TrustInState(HostKeyTrustState state)
    {
        switch (state)
        {
            case HostKeyTrustState.Unconfigured:
                return HostKeyTrust.Unconfigured(TargetEndpoint());
            case HostKeyTrustState.AwaitingProbe:
                return HostKeyTrustServices.CreateCoordinator()
                    .BeginProbe(HostKeyTrust.Unconfigured(TargetEndpoint()));
            case HostKeyTrustState.AwaitingConfirmation:
                var coordinator = HostKeyTrustServices.CreateCoordinator();
                return coordinator.RecordObservation(
                    coordinator.BeginProbe(HostKeyTrust.Unconfigured(TargetEndpoint())),
                    Algorithm,
                    Fingerprint,
                    DateTimeOffset.UtcNow);
            case HostKeyTrustState.Pinned:
                return ConfirmedTrust();
            case HostKeyTrustState.Verified:
                return HostKeyTrustServices.CreateCoordinator()
                    .RecordMatchingObservation(ConfirmedTrust(), DateTimeOffset.UtcNow);
            case HostKeyTrustState.MismatchBlocked:
                return HostKeyTrustServices.CreateCoordinator().RecordMismatchObservation(
                    ConfirmedTrust(),
                    "ssh-rsa",
                    "ssh-rsa 3072 SHA256:different",
                    DateTimeOffset.UtcNow);
            default:
                throw new ArgumentOutOfRangeException(nameof(state), state, null);
        }
    }
}
