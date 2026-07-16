using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
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

public sealed class PlinkSessionTests
{
    private const string CredentialPath = @"C:\Users\tester\AppData\Local\AssessmentTool\CredentialLeases\run-fixture\pw-fixture.tmp";

    [Fact]
    public async Task Password_session_returns_exact_transcript_and_disposes_temporary_credential()
    {
        var stdout = Encoding.UTF8.GetBytes("设备版本 V1.2\r\n");
        var stderr = Encoding.UTF8.GetBytes("warning\r\n");
        var processRunner = new RecordingProcessRunner(ProcessRunResult.Completed(stdout, stderr, 0));
        var leaseFactory = new FakeCredentialLeaseFactory(CredentialPath);
        var diagnostics = new RecordingDiagnostics();
        using (var candidate = CreateCandidate())
        using (var session = new PlinkSession(
                   PasswordProfile(),
                   candidate,
                   leaseFactory,
                   processRunner,
                   diagnostics,
                   Encoding.UTF8,
                   new FixedClock()))
        {
            var output = await session.ExecuteAsync(SafeCommand(), CancellationToken.None);

            Assert.Equal(RemoteExecutionOutcome.Succeeded, output.Outcome);
            Assert.Equal("设备版本 V1.2\r\n", output.StandardOutput);
            Assert.Equal("warning\r\n", output.StandardError);
            Assert.Equal(0, output.ExitCode);
            Assert.True(leaseFactory.Lease.Disposed);
            Assert.Contains("-pwfile", processRunner.ArgumentTokens);
            Assert.Contains(CredentialPath, processRunner.ArgumentTokens);
            Assert.DoesNotContain("raw-password", processRunner.ArgumentTokens);
        }
    }

    [Fact]
    public async Task Private_key_session_uses_only_a_protected_key_lease_path()
    {
        const string privateKeyPath = @"D:\AssessmentTool\PrivateKeys\key-fixture.ppk";
        var processRunner = new RecordingProcessRunner(ProcessRunResult.Completed(
            Array.Empty<byte>(),
            Array.Empty<byte>(),
            0));
        var privateKeyFactory = new FakePrivateKeyLeaseFactory(privateKeyPath);
        using (var candidate = CreateCandidate())
        using (var session = new PlinkSession(
                   PrivateKeyProfile(),
                   candidate,
                   new FakeCredentialLeaseFactory(CredentialPath),
                   privateKeyFactory,
                   processRunner,
                   new RecordingDiagnostics(),
                   Encoding.UTF8,
                   new FixedClock()))
        {
            var output = await session.ExecuteAsync(SafeCommand(), CancellationToken.None);

            Assert.Equal(RemoteExecutionOutcome.Succeeded, output.Outcome);
            Assert.Contains("-i", processRunner.ArgumentTokens);
            Assert.Contains(privateKeyPath, processRunner.ArgumentTokens);
            Assert.DoesNotContain("-pwfile", processRunner.ArgumentTokens);
            Assert.True(privateKeyFactory.Lease.Disposed);
        }
    }

    [Theory]
    [InlineData("Access denied", RemoteFailureCategory.AuthenticationFailed)]
    [InlineData("FATAL ERROR: Host key did not match", RemoteFailureCategory.HostKeyRejected)]
    [InlineData("FATAL ERROR: Network error: Connection refused", RemoteFailureCategory.NetworkFailed)]
    [InlineData("unexpected plink error", RemoteFailureCategory.ProcessFailed)]
    public async Task Nonzero_exit_is_mapped_to_a_safe_chinese_failure_category(
        string standardError,
        RemoteFailureCategory expectedCategory)
    {
        var processRunner = new RecordingProcessRunner(ProcessRunResult.Completed(
            Array.Empty<byte>(),
            Encoding.UTF8.GetBytes(standardError),
            1));
        using (var candidate = CreateCandidate())
        using (var session = CreateSession(candidate, processRunner))
        {
            var output = await session.ExecuteAsync(SafeCommand(), CancellationToken.None);

            Assert.Equal(RemoteExecutionOutcome.Failed, output.Outcome);
            Assert.Equal(expectedCategory, output.FailureCategory);
            Assert.Equal(1, output.ExitCode);
            Assert.False(string.IsNullOrWhiteSpace(output.UserErrorMessage));
            Assert.DoesNotContain(standardError, output.UserErrorMessage);
        }
    }

    [Theory]
    [InlineData("Cancelled", RemoteFailureCategory.Cancelled)]
    [InlineData("TimedOut", RemoteFailureCategory.TimedOut)]
    public async Task Cancellation_and_timeout_are_preserved_as_stopped_results(
        string processOutcomeName,
        RemoteFailureCategory expectedCategory)
    {
        var processOutcome = (ProcessRunOutcome)Enum.Parse(typeof(ProcessRunOutcome), processOutcomeName);
        var processRunner = new RecordingProcessRunner(ProcessRunResult.Stopped(
            processOutcome,
            Encoding.UTF8.GetBytes("partial"),
            Array.Empty<byte>()));
        var leaseFactory = new FakeCredentialLeaseFactory(CredentialPath);
        using (var candidate = CreateCandidate())
        using (var session = new PlinkSession(
                   PasswordProfile(),
                   candidate,
                   leaseFactory,
                   processRunner,
                   new RecordingDiagnostics(),
                   Encoding.UTF8,
                   new FixedClock()))
        {
            var output = await session.ExecuteAsync(SafeCommand(), CancellationToken.None);

            Assert.Equal(RemoteExecutionOutcome.Stopped, output.Outcome);
            Assert.Equal(expectedCategory, output.FailureCategory);
            Assert.Equal("partial", output.StandardOutput);
            Assert.True(leaseFactory.Lease.Disposed);
        }
    }

    [Fact]
    public async Task Unsafe_command_is_rejected_before_credential_or_process_creation()
    {
        var processRunner = new RecordingProcessRunner(ProcessRunResult.Completed(
            Array.Empty<byte>(),
            Array.Empty<byte>(),
            0));
        var leaseFactory = new FakeCredentialLeaseFactory(CredentialPath);
        using (var candidate = CreateCandidate())
        using (var session = new PlinkSession(
                   PasswordProfile(),
                   candidate,
                   leaseFactory,
                   processRunner,
                   new RecordingDiagnostics(),
                   Encoding.UTF8,
                   new FixedClock()))
        {
            var output = await session.ExecuteAsync(
                CreateCommand("display version | configure terminal"),
                CancellationToken.None);

            Assert.Equal(RemoteFailureCategory.UnsafeCommand, output.FailureCategory);
            Assert.Equal(0, processRunner.CallCount);
            Assert.Equal(0, leaseFactory.CreateCount);
        }
    }

    [Fact]
    public async Task Diagnostics_never_receive_the_temporary_credential_path_or_raw_transcript()
    {
        var processRunner = new RecordingProcessRunner(ProcessRunResult.Failed(
            ProcessFailureStage.ProcessCreation,
            "process-creation-failed",
            5,
            Array.Empty<byte>(),
            Encoding.UTF8.GetBytes("customer-sensitive-output")));
        var diagnostics = new RecordingDiagnostics();
        using (var candidate = CreateCandidate())
        using (var session = new PlinkSession(
                   PasswordProfile(),
                   candidate,
                   new FakeCredentialLeaseFactory(CredentialPath, CredentialPath),
                   processRunner,
                   diagnostics,
                   Encoding.UTF8,
                   new FixedClock()))
        {
            _ = await session.ExecuteAsync(SafeCommand(), CancellationToken.None);

            var diagnosticText = string.Join("|", diagnostics.Events.Select(value => value.ToString()));
            Assert.DoesNotContain(CredentialPath, diagnosticText);
            Assert.DoesNotContain("customer-sensitive-output", diagnosticText);
            Assert.Contains("credential-redacted", diagnosticText);
        }
    }

    private static PlinkSession CreateSession(
        ComponentExecutionCandidate candidate,
        RecordingProcessRunner processRunner)
    {
        return new PlinkSession(
            PasswordProfile(),
            candidate,
            new FakeCredentialLeaseFactory(CredentialPath),
            processRunner,
            new RecordingDiagnostics(),
            Encoding.UTF8,
            new FixedClock());
    }

    private static ConnectionProfile PasswordProfile()
    {
        return Profile(SshAuthenticationMethod.Password);
    }

    private static ConnectionProfile PrivateKeyProfile()
    {
        return Profile(SshAuthenticationMethod.PrivateKey);
    }

    private static ConnectionProfile Profile(SshAuthenticationMethod authenticationMethod)
    {
        var endpoint = new SshEndpointIdentity("router.example.test", 22);
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var observedAt = new DateTimeOffset(2026, 7, 16, 8, 0, 0, TimeSpan.Zero);
        var awaiting = coordinator.RecordObservation(
            coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint)),
            "ssh-ed25519",
            "ssh-ed25519 255 SHA256:fixture",
            observedAt);
        var trust = coordinator.Confirm(awaiting, observedAt.AddMinutes(1), "设备控制台核对");
        return new ConnectionProfile(
            "核心交换机",
            endpoint.Host,
            endpoint.Port,
            ConnectionProtocol.Ssh,
            new SshConnectionOptions(
                endpoint,
                "audit-user",
                authenticationMethod,
                CredentialReference.New(),
                authenticationMethod == SshAuthenticationMethod.PrivateKey
                    ? PrivateKeyReference.New()
                    : (PrivateKeyReference?)null,
                trust));
    }

    private static CommandDefinition SafeCommand()
    {
        return CreateCommand("display version");
    }

    private static CommandDefinition CreateCommand(string commandText)
    {
        var constructor = Assert.Single(
            typeof(CommandDefinition).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic));
        return (CommandDefinition)constructor.Invoke(new object?[]
        {
            "cmd-version",
            "查询版本",
            TargetCategory.NetworkDevice,
            commandText,
            VerificationStatus.Verified,
            true,
            "Vendor",
            "Series",
            "1.0",
            "2.0",
            "1.1.1",
            "all",
            "readonly",
            CommandRiskLevel.Low,
            TimeSpan.FromSeconds(5),
            PagingBehavior.NotApplicable,
            "版本信息",
            new DateTime(2026, 7, 16),
            "https://vendor.example/docs"
        });
    }

    private static ComponentExecutionCandidate CreateCandidate()
    {
        const string path = @"C:\Assessment Tool\components\plink.exe";
        return new ComponentExecutionCandidate(
            "plink",
            new ComponentFileIdentity(
                path,
                new string('a', 64),
                128,
                new DateTime(2026, 7, 16, 0, 0, 0, DateTimeKind.Utc),
                1,
                2,
                1),
            path,
            new FakeComponentHandle());
    }

    private sealed class RecordingProcessRunner : IProcessRunner
    {
        private readonly ProcessRunResult result;

        internal RecordingProcessRunner(ProcessRunResult result)
        {
            this.result = result;
        }

        internal IReadOnlyList<string> ArgumentTokens { get; private set; } = Array.Empty<string>();
        internal int CallCount { get; private set; }

        public Task<ProcessRunResult> RunAsync(
            ComponentExecutionCandidate executable,
            ProcessRunRequest request,
            CancellationToken cancellationToken)
        {
            CallCount++;
            ArgumentTokens = request.ArgumentTokens.ToArray();
            return Task.FromResult(result);
        }
    }

    private sealed class FakeCredentialLeaseFactory : ICredentialLeaseFactory
    {
        private readonly string path;

        internal FakeCredentialLeaseFactory(
            string path,
            string redactedIdentifier = "plink-credential-fixture")
        {
            this.path = path;
            Lease = new FakeCredentialFileLease(path, redactedIdentifier);
        }

        internal FakeCredentialFileLease Lease { get; }
        internal int CreateCount { get; private set; }

        public ICredentialFileLease Create(
            CredentialReference credentialReference,
            CancellationToken cancellationToken = default)
        {
            CreateCount++;
            return Lease;
        }
    }

    private sealed class FakeCredentialFileLease : ICredentialFileLease
    {
        internal FakeCredentialFileLease(string path, string redactedIdentifier)
        {
            Path = path;
            RedactedIdentifier = redactedIdentifier;
        }

        public string Path { get; }
        public string RedactedIdentifier { get; }
        internal bool Disposed { get; private set; }

        public void Dispose()
        {
            Disposed = true;
        }
    }

    private sealed class FakePrivateKeyLeaseFactory : IPrivateKeyFileLeaseFactory
    {
        internal FakePrivateKeyLeaseFactory(string path)
        {
            Lease = new FakePrivateKeyFileLease(path);
        }

        internal FakePrivateKeyFileLease Lease { get; }

        public IPrivateKeyFileLease Create(
            PrivateKeyReference privateKeyReference,
            CancellationToken cancellationToken)
        {
            return Lease;
        }
    }

    private sealed class FakePrivateKeyFileLease : IPrivateKeyFileLease
    {
        internal FakePrivateKeyFileLease(string path)
        {
            Path = path;
        }

        public string Path { get; }
        public string RedactedIdentifier => "plink-private-key-fixture";
        internal bool Disposed { get; private set; }

        public void Dispose()
        {
            Disposed = true;
        }
    }

    private sealed class RecordingDiagnostics : IPlinkSessionDiagnostics
    {
        internal List<PlinkSessionDiagnostic> Events { get; } = new List<PlinkSessionDiagnostic>();

        public void Record(PlinkSessionDiagnostic diagnostic)
        {
            Events.Add(diagnostic);
        }
    }

    private sealed class FixedClock : IPlinkSessionClock
    {
        private int reads;

        public DateTimeOffset UtcNow => new DateTimeOffset(2026, 7, 16, 8, reads++, 0, TimeSpan.Zero);
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
