using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Components;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Processes;
using AssessmentTool.Windows.Sessions;
using Xunit;

namespace AssessmentTool.Windows.Tests.Sessions;

public sealed class PlinkNoCommandLoginTesterTests
{
    private const string CredentialPath = @"C:\AssessmentTool\CredentialLeases\login-test\pw.tmp";
    private const string PrivateKeyPath = @"C:\AssessmentTool\PrivateKeyLeases\login-test\key.ppk";

    [Fact]
    public async Task Confirmed_profile_uses_N_and_zero_standard_input_then_accepts_explicit_success_marker()
    {
        var runner = new RecordingRunner(ProcessRunResult.Stopped(
            ProcessRunOutcome.TimedOut,
            Array.Empty<byte>(),
            Encoding.UTF8.GetBytes("Access granted\r\nOpening main session")));
        var credentials = new RecordingCredentialFactory();
        using (var candidate = CreateCandidate())
        {
            var result = await new PlinkNoCommandLoginTester(credentials, runner, Encoding.UTF8)
                .TestAsync(candidate, ConfirmedProfile(), CancellationToken.None);

            Assert.Equal(NoCommandLoginOutcome.Succeeded, result.Outcome);
            Assert.Equal(1, credentials.CreateCount);
            Assert.True(credentials.Lease.Disposed);
            Assert.Contains("-N", runner.ArgumentTokens);
            Assert.Contains("-T", runner.ArgumentTokens);
            Assert.Contains("-noagent", runner.ArgumentTokens);
            Assert.Contains("-noshare", runner.ArgumentTokens);
            Assert.Contains("-hostkey", runner.ArgumentTokens);
            Assert.Contains("-pwfile", runner.ArgumentTokens);
            Assert.DoesNotContain("display version", runner.ArgumentTokens);
            Assert.Empty(runner.Request!.GetStandardInputBytes());
        }
    }

    [Fact]
    public async Task Unconfirmed_profile_is_blocked_before_password_is_read_or_process_is_started()
    {
        var runner = new RecordingRunner(ProcessRunResult.Completed(Array.Empty<byte>(), Array.Empty<byte>(), 0));
        var credentials = new RecordingCredentialFactory();
        using (var candidate = CreateCandidate())
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                new PlinkNoCommandLoginTester(credentials, runner, Encoding.UTF8)
                    .TestAsync(candidate, UnconfirmedProfile(), CancellationToken.None));

            Assert.Equal(0, credentials.CreateCount);
            Assert.Equal(0, runner.CallCount);
        }
    }

    [Fact]
    public async Task Timeout_without_success_marker_is_not_reported_as_success()
    {
        var runner = new RecordingRunner(ProcessRunResult.Stopped(
            ProcessRunOutcome.TimedOut,
            Array.Empty<byte>(),
            Encoding.UTF8.GetBytes("Connecting to server")));
        using (var candidate = CreateCandidate())
        {
            var result = await new PlinkNoCommandLoginTester(
                    new RecordingCredentialFactory(), runner, Encoding.UTF8)
                .TestAsync(candidate, ConfirmedProfile(), CancellationToken.None);

            Assert.Equal(NoCommandLoginOutcome.TimedOut, result.Outcome);
        }
    }

    [Fact]
    public async Task Confirmed_private_key_profile_uses_controlled_key_without_reading_password()
    {
        var runner = new RecordingRunner(ProcessRunResult.Stopped(
            ProcessRunOutcome.TimedOut,
            Array.Empty<byte>(),
            Encoding.UTF8.GetBytes("Access granted\r\nOpening main session")));
        var credentials = new RecordingCredentialFactory();
        var privateKeys = new RecordingPrivateKeyFactory();
        using (var candidate = CreateCandidate())
        {
            var result = await new PlinkNoCommandLoginTester(
                    credentials, privateKeys, runner, Encoding.UTF8)
                .TestAsync(candidate, ConfirmedPrivateKeyProfile(), CancellationToken.None);

            Assert.Equal(NoCommandLoginOutcome.Succeeded, result.Outcome);
            Assert.Equal(0, credentials.CreateCount);
            Assert.Equal(1, privateKeys.CreateCount);
            Assert.True(privateKeys.Lease.Disposed);
            Assert.Contains("-i", runner.ArgumentTokens);
            Assert.Contains(PrivateKeyPath, runner.ArgumentTokens);
            Assert.DoesNotContain("-pwfile", runner.ArgumentTokens);
            Assert.Contains("-N", runner.ArgumentTokens);
            Assert.Empty(runner.Request!.GetStandardInputBytes());
        }
    }

    private static ConnectionProfile ConfirmedProfile()
    {
        var endpoint = new SshEndpointIdentity("router.example.test", 22);
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var observedAt = new DateTimeOffset(2026, 7, 17, 8, 0, 0, TimeSpan.Zero);
        var observed = coordinator.RecordObservation(
            coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint)),
            "ssh-ed25519",
            "ssh-ed25519 255 SHA256:fixture",
            observedAt);
        return Profile(coordinator.Confirm(observed, observedAt.AddMinutes(1), "客户控制台核对"));
    }

    private static ConnectionProfile UnconfirmedProfile()
    {
        var endpoint = new SshEndpointIdentity("router.example.test", 22);
        return Profile(HostKeyTrust.Unconfigured(endpoint));
    }

    private static ConnectionProfile ConfirmedPrivateKeyProfile()
    {
        var endpoint = new SshEndpointIdentity("router.example.test", 22);
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var observedAt = new DateTimeOffset(2026, 7, 18, 8, 0, 0, TimeSpan.Zero);
        var observed = coordinator.RecordObservation(
            coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint)),
            "ssh-ed25519",
            "ssh-ed25519 255 SHA256:fixture",
            observedAt);
        var trust = coordinator.Confirm(observed, observedAt.AddMinutes(1), "客户控制台核对");
        return new ConnectionProfile(
            "核心交换机",
            endpoint.Host,
            endpoint.Port,
            ConnectionProtocol.Ssh,
            new SshConnectionOptions(
                endpoint,
                "audit-user",
                SshAuthenticationMethod.PrivateKey,
                CredentialReference.New(),
                PrivateKeyReference.New(),
                trust));
    }

    private static ConnectionProfile Profile(HostKeyTrust trust)
    {
        var endpoint = trust.Endpoint;
        return new ConnectionProfile(
            "核心交换机",
            endpoint.Host,
            endpoint.Port,
            ConnectionProtocol.Ssh,
            new SshConnectionOptions(
                endpoint,
                "audit-user",
                SshAuthenticationMethod.Password,
                CredentialReference.New(),
                null,
                trust));
    }

    private static ComponentExecutionCandidate CreateCandidate()
    {
        const string path = @"C:\Assessment Tool\components\plink.exe";
        return new ComponentExecutionCandidate(
            "plink",
            new ComponentFileIdentity(path, new string('a', 64), 128, DateTime.UtcNow, 1, 2, 1),
            path,
            new FakeComponentHandle());
    }

    private sealed class RecordingRunner : IProcessRunner
    {
        private readonly ProcessRunResult result;

        internal RecordingRunner(ProcessRunResult result)
        {
            this.result = result;
        }

        internal int CallCount { get; private set; }
        internal ProcessRunRequest? Request { get; private set; }
        internal IReadOnlyList<string> ArgumentTokens { get; private set; } = Array.Empty<string>();

        public Task<ProcessRunResult> RunAsync(
            ComponentExecutionCandidate executable,
            ProcessRunRequest request,
            CancellationToken cancellationToken)
        {
            CallCount++;
            Request = request;
            ArgumentTokens = request.ArgumentTokens.ToArray();
            return Task.FromResult(result);
        }
    }

    private sealed class RecordingCredentialFactory : ICredentialLeaseFactory
    {
        internal RecordingCredentialFactory()
        {
            Lease = new RecordingCredentialLease();
        }

        internal int CreateCount { get; private set; }
        internal RecordingCredentialLease Lease { get; }

        public ICredentialFileLease Create(
            CredentialReference credentialReference,
            CancellationToken cancellationToken = default)
        {
            CreateCount++;
            return Lease;
        }
    }

    private sealed class RecordingCredentialLease : ICredentialFileLease
    {
        public string Path => CredentialPath;
        public string RedactedIdentifier => "login-test-credential";
        internal bool Disposed { get; private set; }

        public void Dispose()
        {
            Disposed = true;
        }
    }

    private sealed class RecordingPrivateKeyFactory : IPrivateKeyFileLeaseFactory
    {
        internal RecordingPrivateKeyFactory()
        {
            Lease = new RecordingPrivateKeyLease();
        }

        internal int CreateCount { get; private set; }
        internal RecordingPrivateKeyLease Lease { get; }

        public IPrivateKeyFileLease Create(
            PrivateKeyReference privateKeyReference,
            CancellationToken cancellationToken)
        {
            CreateCount++;
            return Lease;
        }
    }

    private sealed class RecordingPrivateKeyLease : IPrivateKeyFileLease
    {
        public string Path => PrivateKeyPath;
        public string RedactedIdentifier => "login-test-private-key";
        internal bool Disposed { get; private set; }

        public void Dispose()
        {
            Disposed = true;
        }
    }

    private sealed class FakeComponentHandle : IComponentFileHandle
    {
        public Stream Stream { get; } = new MemoryStream(new byte[] { 1 }, writable: false);

        public ComponentHandleSnapshot CaptureSnapshot()
        {
            throw new NotSupportedException();
        }

        public void ValidateLease()
        {
        }

        public void Dispose()
        {
            Stream.Dispose();
        }
    }
}
