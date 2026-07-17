using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Execution;
using AssessmentTool.Core.Security;
using AssessmentTool.Windows.Credentials;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class CollectionWorkflowServiceTests
{
    private const string Algorithm = "ssh-ed25519";
    private const string Fingerprint = "ssh-ed25519 255 SHA256:collection-workflow-fixture";

    public static IEnumerable<object[]> UnsupportedTargets()
    {
        yield return new object[] { ConnectionProtocol.Telnet, TargetCategory.Server };
        yield return new object[] { ConnectionProtocol.Serial, TargetCategory.Server };
        yield return new object[] { ConnectionProtocol.WinRm, TargetCategory.Server };
        yield return new object[] { ConnectionProtocol.Ssh, TargetCategory.NetworkDevice };
        yield return new object[] { ConnectionProtocol.Ssh, TargetCategory.Database };
        yield return new object[] { ConnectionProtocol.Ssh, TargetCategory.Middleware };
        yield return new object[] { ConnectionProtocol.Ssh, TargetCategory.SecurityDevice };
    }

    [Theory]
    [MemberData(nameof(UnsupportedTargets))]
    public async Task Unsupported_target_is_rejected_before_credentials_connection_or_evidence(
        ConnectionProtocol protocol,
        TargetCategory category)
    {
        var fixture = CreateFixture(protocol, category, HostKeyTrustState.Verified);

        var result = await fixture.Service.RunAsync(
            fixture.Request,
            fixture.Progress,
            CancellationToken.None);

        Assert.Equal(CollectionWorkflowOutcome.Failed, result.Outcome);
        Assert.NotNull(result.Error);
        Assert.Equal("UnsupportedCollectionTarget", result.Error!.TechnicalDetails);
        Assert.Empty(result.CompletedCommands);
        Assert.Equal(0, fixture.Vault.OperationCount);
        Assert.Equal(0, fixture.Evidence.SaveCount);
        Assert.Equal(0, fixture.Progress.ReportCount);
    }

    [Theory]
    [InlineData(HostKeyTrustState.Unconfigured)]
    [InlineData(HostKeyTrustState.AwaitingProbe)]
    [InlineData(HostKeyTrustState.AwaitingConfirmation)]
    [InlineData(HostKeyTrustState.MismatchBlocked)]
    public async Task Unconfirmed_or_blocked_host_key_is_rejected_before_credentials_connection_or_evidence(
        HostKeyTrustState trustState)
    {
        var fixture = CreateFixture(ConnectionProtocol.Ssh, TargetCategory.Server, trustState);

        var result = await fixture.Service.RunAsync(
            fixture.Request,
            fixture.Progress,
            CancellationToken.None);

        Assert.Equal(CollectionWorkflowOutcome.Failed, result.Outcome);
        Assert.NotNull(result.Error);
        Assert.Equal("HostKeyTrustNotEligible", result.Error!.TechnicalDetails);
        Assert.Contains("指纹", result.Error.Summary);
        Assert.Empty(result.CompletedCommands);
        Assert.Equal(0, fixture.Vault.OperationCount);
        Assert.Equal(0, fixture.Evidence.SaveCount);
        Assert.Equal(0, fixture.Progress.ReportCount);
    }

    [Fact]
    public async Task Missing_trusted_component_is_rejected_before_credentials_or_evidence()
    {
        var project = CreateProject();
        var device = CreateDevice(
            project,
            ConnectionProtocol.Ssh,
            TargetCategory.Server,
            "192.0.2.41",
            "audit-user");
        var vault = new GuardCredentialVault();
        var evidence = new GuardEvidenceService();
        var service = new CollectionWorkflowService(vault, evidence);
        var request = new CollectionWorkflowRequest(
            project,
            new CollectionDeviceSelection(
                device,
                isRequiredComponentAvailable: false,
                hostKeyTrust: CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified)));

        var result = await service.RunAsync(request, new CountingProgress(), CancellationToken.None);

        Assert.Equal(CollectionWorkflowOutcome.Failed, result.Outcome);
        Assert.Equal("RequiredComponentUnavailable", result.Error!.TechnicalDetails);
        Assert.Equal(0, vault.OperationCount);
        Assert.Equal(0, evidence.SaveCount);
    }

    [Fact]
    public void Generic_linux_collection_pack_contains_only_the_explicit_collection_subset()
    {
        var releaseDirectory = Path.Combine(
            Path.GetTempPath(),
            "EvaluationTool.CollectionWorkflow.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(releaseDirectory);
        try
        {
            var catalog = new BuiltinCommandPackCatalog(releaseDirectory);
            var fullPack = catalog.LoadGenericLinux();
            var collectionPack = catalog.CreateGenericLinuxCollectionPack(fullPack);
            var collectionCommands = catalog.SelectGenericLinuxCollectionCommands(fullPack);

        Assert.Equal(
            new[] { "generic-linux-hostname", "generic-linux-login-defs" },
            collectionPack.Commands.Select(command => command.Id));
            Assert.Equal(collectionCommands.Select(command => command.Id), collectionPack.Commands.Select(command => command.Id));
            Assert.DoesNotContain(collectionPack.Commands, command =>
                catalog.GenericLinuxIdentificationCommandIds.Contains(command.Id));
            Assert.All(collectionPack.Commands, command =>
                Assert.True(new CommandSafetyPolicy().Validate(command).Allowed));
            Assert.Equal(fullPack.Id, collectionPack.Id);
            Assert.Equal(fullPack.Version, collectionPack.Version);
            Assert.Equal(fullPack.Sha256, collectionPack.Sha256);
            Assert.Equal(fullPack.OfficialSource, collectionPack.OfficialSource);
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task Early_rejection_errors_do_not_disclose_device_or_credential_identifiers()
    {
        const string sensitiveHost = "host-secret.example.test";
        const string sensitiveUser = "token=user-secret";
        var project = CreateProject();
        var device = CreateDevice(
            project,
            ConnectionProtocol.Ssh,
            TargetCategory.Database,
            sensitiveHost,
            sensitiveUser);
        var trust = CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        var vault = new GuardCredentialVault();
        var evidence = new GuardEvidenceService();
        var service = new CollectionWorkflowService(vault, evidence);

        var result = await service.RunAsync(
            CreateRequest(project, device, trust),
            new CountingProgress(),
            CancellationToken.None);

        var errorText = JoinError(result.Error);
        Assert.DoesNotContain(sensitiveHost, errorText);
        Assert.DoesNotContain("host-secret", errorText);
        Assert.DoesNotContain(sensitiveUser, errorText);
        Assert.DoesNotContain("user-secret", errorText);
        Assert.DoesNotContain(device.CredentialReference.ToString(), errorText);
        Assert.Equal(0, vault.OperationCount);
        Assert.Equal(0, evidence.SaveCount);
    }

    [Fact]
    public void Unexpected_exception_mapping_is_static_and_does_not_copy_exception_messages()
    {
        var servicePath = Path.Combine(
            FindRepositoryRoot(),
            "src",
            "AssessmentTool.App",
            "Services",
            "CollectionWorkflowService.cs");
        var source = File.ReadAllText(servicePath);

        Assert.Contains("exception.GetType().Name", source);
        Assert.DoesNotContain("exception.Message", source);
        Assert.DoesNotContain("exception.ToString()", source);
        Assert.DoesNotContain("exception.StackTrace", source);
    }

    private static WorkflowFixture CreateFixture(
        ConnectionProtocol protocol,
        TargetCategory category,
        HostKeyTrustState trustState)
    {
        var project = CreateProject();
        var device = CreateDevice(project, protocol, category, "192.0.2.40", "audit-user");
        var trust = CreateTrust(device.Host, device.Port, trustState);
        var vault = new GuardCredentialVault();
        var evidence = new GuardEvidenceService();
        var progress = new CountingProgress();
        return new WorkflowFixture(
            new CollectionWorkflowService(vault, evidence),
            CreateRequest(project, device, trust),
            vault,
            evidence,
            progress);
    }

    private static ProjectRecord CreateProject()
    {
        return new ProjectRecord(
            ProjectId.New(),
            "测试客户",
            "采集工作流测试项目",
            @"C:\Evidence",
            new DateTimeOffset(2026, 7, 17, 0, 0, 0, TimeSpan.Zero));
    }

    private static DeviceRecord CreateDevice(
        ProjectRecord project,
        ConnectionProtocol protocol,
        TargetCategory category,
        string host,
        string userName)
    {
        return new DeviceRecord(
            DeviceId.New(),
            project.Id,
            "测试设备",
            host,
            22,
            userName,
            category,
            protocol,
            CredentialReference.New(),
            new DateTimeOffset(2026, 7, 17, 0, 1, 0, TimeSpan.Zero));
    }

    private static CollectionWorkflowRequest CreateRequest(
        ProjectRecord project,
        DeviceRecord device,
        HostKeyTrust trust)
    {
        return new CollectionWorkflowRequest(
            project,
            new CollectionDeviceSelection(
                device,
                isRequiredComponentAvailable: true,
                hostKeyTrust: trust));
    }

    private static HostKeyTrust CreateTrust(string host, int port, HostKeyTrustState state)
    {
        var endpoint = new SshEndpointIdentity(host, port);
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        if (state == HostKeyTrustState.Unconfigured)
        {
            return HostKeyTrust.Unconfigured(endpoint);
        }

        var probing = coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint));
        if (state == HostKeyTrustState.AwaitingProbe)
        {
            return probing;
        }

        var observedAt = new DateTimeOffset(2026, 7, 17, 0, 2, 0, TimeSpan.Zero);
        var awaiting = coordinator.RecordObservation(probing, Algorithm, Fingerprint, observedAt);
        if (state == HostKeyTrustState.AwaitingConfirmation)
        {
            return awaiting;
        }

        var pinned = coordinator.Confirm(awaiting, observedAt.AddMinutes(1), "测试中人工核对指纹");
        if (state == HostKeyTrustState.Pinned)
        {
            return pinned;
        }

        if (state == HostKeyTrustState.Verified)
        {
            return coordinator.RecordMatchingObservation(pinned, observedAt.AddMinutes(2));
        }

        if (state == HostKeyTrustState.MismatchBlocked)
        {
            return coordinator.RecordMismatchObservation(
                pinned,
                "ssh-rsa",
                "ssh-rsa 3072 SHA256:different-collection-workflow-fixture",
                observedAt.AddMinutes(2));
        }

        throw new ArgumentOutOfRangeException(nameof(state), state, null);
    }

    private static string JoinError(CollectionError? error)
    {
        Assert.NotNull(error);
        return string.Join("|", new[]
        {
            error!.Summary,
            error.PossibleCause,
            error.RecommendedAction,
            error.TechnicalDetails
        });
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "src"))
                && Directory.Exists(Path.Combine(directory.FullName, "tests")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Unable to locate repository root.");
    }

    private sealed class WorkflowFixture
    {
        public WorkflowFixture(
            CollectionWorkflowService service,
            CollectionWorkflowRequest request,
            GuardCredentialVault vault,
            GuardEvidenceService evidence,
            CountingProgress progress)
        {
            Service = service;
            Request = request;
            Vault = vault;
            Evidence = evidence;
            Progress = progress;
        }

        public CollectionWorkflowService Service { get; }
        public CollectionWorkflowRequest Request { get; }
        public GuardCredentialVault Vault { get; }
        public GuardEvidenceService Evidence { get; }
        public CountingProgress Progress { get; }
    }

    private sealed class GuardCredentialVault : ICredentialVault
    {
        public int OperationCount { get; private set; }

        public CredentialReference Store(char[] secret, CancellationToken cancellationToken = default)
        {
            OperationCount++;
            throw new InvalidOperationException("拒绝路径不得写入凭据库。");
        }

        public char[] Retrieve(CredentialReference reference)
        {
            OperationCount++;
            throw new InvalidOperationException("拒绝路径不得读取凭据库。");
        }

        public void Delete(CredentialReference reference)
        {
            OperationCount++;
            throw new InvalidOperationException("拒绝路径不得删除凭据。");
        }
    }

    private sealed class GuardEvidenceService : ICollectionEvidenceService
    {
        public int SaveCount { get; private set; }

        public Task<SavedCollectionEvidence> SaveAsync(
            ProjectRecord project,
            DeviceRecord device,
            string commandPackVersion,
            CommandDefinition command,
            CommandOutput output,
            CancellationToken cancellationToken = default)
        {
            SaveCount++;
            throw new InvalidOperationException("拒绝路径不得保存证据。");
        }
    }

    private sealed class CountingProgress : IProgress<CollectionProgress>
    {
        public int ReportCount { get; private set; }

        public void Report(CollectionProgress value)
        {
            ReportCount++;
        }
    }
}
