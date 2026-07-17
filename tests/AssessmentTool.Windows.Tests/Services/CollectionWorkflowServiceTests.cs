using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Execution;
using AssessmentTool.Core.Security;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Storage;
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
    public async Task Completed_linux_collection_discovers_databases_saves_all_outputs_and_requires_confirmation()
    {
        var project = CreateProject();
        var device = CreateDevice(project, ConnectionProtocol.Ssh, TargetCategory.Server, "192.0.2.42", "audit-user");
        var trust = CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        var session = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["generic-linux-uname-a"] = Success("generic-linux-uname-a", "Linux audit-host 6.8.0 x86_64 GNU/Linux"),
            ["generic-linux-os-release"] = Success("generic-linux-os-release", "ID=ubuntu\nVERSION_ID=24.04"),
            ["generic-linux-hostname"] = Success("generic-linux-hostname", "audit-host"),
            ["generic-linux-login-defs"] = Success("generic-linux-login-defs", "PASS_MAX_DAYS 90"),
            ["database-host-discovery-linux-processes"] = Success("database-host-discovery-linux-processes", "101 postgres-16"),
            ["database-host-discovery-linux-services"] = Success(
                "database-host-discovery-linux-services",
                "postgresql@16-main.service loaded active running PostgreSQL Cluster 16-main"),
            ["database-host-discovery-linux-docker-containers"] = MissingOptional("database-host-discovery-linux-docker-containers"),
            ["database-host-discovery-linux-podman-containers"] = MissingOptional("database-host-discovery-linux-podman-containers")
        });
        var evidence = new RecordingEvidenceService();
        var identifications = new RecordingIdentificationRepository();
        var releaseDirectory = Path.Combine(Path.GetTempPath(), "EvaluationTool.Workflow.Database", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(releaseDirectory);
        try
        {
            var service = new CollectionWorkflowService(
                new BuiltinCommandPackCatalog(releaseDirectory),
                _ => session,
                evidence,
                identifications);

            var result = await service.RunAsync(
                CreateRequest(project, device, trust),
                new CountingProgress(),
                CancellationToken.None);

            Assert.True(
                result.Outcome == CollectionWorkflowOutcome.RequiresDatabaseConfirmation,
                "Actual outcome: " + result.Outcome + "; error: "
                + (result.Error == null ? "none" : JoinError(result.Error)));
            var candidate = Assert.Single(result.DatabaseCandidates);
            Assert.Equal("PostgreSQL", candidate.Product);
            Assert.Equal("16", candidate.Version);
            Assert.True(candidate.RequiresUserConfirmation);
            Assert.Equal(8, session.ExecutedIds.Count);
            Assert.Equal(session.ExecutedIds, evidence.SavedCommandIds);
            var identification = Assert.Single(identifications.Records);
            Assert.Equal(device.Id, identification.DeviceId);
            Assert.Equal("ubuntu", identification.Vendor);
            Assert.False(identification.WasUserConfirmed);
            var task = Assert.Single(identifications.Tasks);
            Assert.Equal(device.Id, task.DeviceId);
            Assert.Equal(8, task.Commands.Count);
            var taskEvents = identifications.TaskEvents[task.Id];
            Assert.Equal(CollectionTaskState.Ready, taskEvents.First().State);
            Assert.Equal(CollectionTaskState.Completed, taskEvents.Last().State);
            Assert.Equal(8, taskEvents.Count(item => item.EventCode == "CommandEvidenceCommitted"));
            Assert.Equal(
                new[]
                {
                    "generic-linux-hostname",
                    "generic-linux-login-defs",
                    "database-host-discovery-linux-processes",
                    "database-host-discovery-linux-services"
                },
                result.CompletedCommands.Select(command => command.CommandId));
            Assert.True(session.Disposed);
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task Ambiguous_detection_is_persisted_then_revalidated_before_collection()
    {
        var project = CreateProject();
        var device = CreateDevice(project, ConnectionProtocol.Ssh, TargetCategory.Server, "192.0.2.43", "audit-user");
        var trust = CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        var firstSession = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["generic-linux-uname-a"] = Success("generic-linux-uname-a", "Linux audit-host 6.8.0 x86_64 GNU/Linux"),
            ["generic-linux-os-release"] = Success("generic-linux-os-release", "ID=ubuntu\nID=kylin")
        });
        var secondSession = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["generic-linux-uname-a"] = Success("generic-linux-uname-a", "Linux audit-host 6.8.0 x86_64 GNU/Linux"),
            ["generic-linux-os-release"] = Success("generic-linux-os-release", "ID=ubuntu\nID=kylin"),
            ["generic-linux-hostname"] = Success("generic-linux-hostname", "audit-host"),
            ["generic-linux-login-defs"] = Success("generic-linux-login-defs", "PASS_MAX_DAYS 90"),
            ["database-host-discovery-linux-processes"] = Success("database-host-discovery-linux-processes", string.Empty),
            ["database-host-discovery-linux-services"] = Success("database-host-discovery-linux-services", string.Empty),
            ["database-host-discovery-linux-docker-containers"] = MissingOptional("database-host-discovery-linux-docker-containers"),
            ["database-host-discovery-linux-podman-containers"] = MissingOptional("database-host-discovery-linux-podman-containers")
        });
        var sessions = new Queue<ScriptedRemoteSession>(new[] { firstSession, secondSession });
        var evidence = new RecordingEvidenceService();
        var identifications = new RecordingIdentificationRepository();
        var releaseDirectory = Path.Combine(Path.GetTempPath(), "EvaluationTool.Workflow.Pending", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(releaseDirectory);
        try
        {
            var service = new CollectionWorkflowService(
                new BuiltinCommandPackCatalog(releaseDirectory),
                _ => sessions.Dequeue(),
                evidence,
                identifications);

            var result = await service.RunAsync(
                CreateRequest(project, device, trust),
                new CountingProgress(),
                CancellationToken.None);

            Assert.Equal(CollectionWorkflowOutcome.RequiresConfirmation, result.Outcome);
            Assert.True(result.PendingIdentificationBatchId.HasValue);
            var pending = Assert.Single(identifications.PendingBatches);
            Assert.Equal(result.PendingIdentificationBatchId, pending.BatchId);
            Assert.Equal(new[] { "kylin", "ubuntu" },
                pending.Candidates.Select(candidate => candidate.Vendor).OrderBy(vendor => vendor));
            Assert.Equal(
                new[] { "generic-linux-uname-a", "generic-linux-os-release" },
                firstSession.ExecutedIds);
            Assert.Empty(identifications.Records);

            var completed = await service.RunAsync(
                CreateRequest(
                    project,
                    device,
                    trust,
                    result.DetectionCandidates.Single(candidate => candidate.Vendor == "ubuntu"),
                    pending.BatchId),
                new CountingProgress(),
                CancellationToken.None);

            Assert.Equal(CollectionWorkflowOutcome.Completed, completed.Outcome);
            var identification = Assert.Single(identifications.Records);
            Assert.True(identification.WasUserConfirmed);
            Assert.Equal("ubuntu", identification.Vendor);
            Assert.Equal(pending.BatchId, Assert.Single(identifications.Resolutions).BatchId);
            Assert.Equal(
                PendingIdentificationResolution.RevalidatedAndCompleted,
                identifications.Resolutions[0].Resolution);
            Assert.Equal(8, secondSession.ExecutedIds.Count);
            var task = Assert.Single(identifications.Tasks);
            Assert.Equal(CollectionTaskState.Completed, identifications.TaskEvents[task.Id].Last().State);
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task Changed_high_confidence_identity_supersedes_stale_pending_batch_without_collecting()
    {
        var project = CreateProject();
        var device = CreateDevice(project, ConnectionProtocol.Ssh, TargetCategory.Server, "192.0.2.44", "audit-user");
        var trust = CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        var firstSession = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["generic-linux-uname-a"] = Success("generic-linux-uname-a", "Linux audit-host 6.8.0 x86_64 GNU/Linux"),
            ["generic-linux-os-release"] = Success("generic-linux-os-release", "ID=ubuntu\nID=kylin")
        });
        var secondSession = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["generic-linux-uname-a"] = Success("generic-linux-uname-a", "Linux audit-host 6.8.0 x86_64 GNU/Linux"),
            ["generic-linux-os-release"] = Success("generic-linux-os-release", "ID=ubuntu")
        });
        var sessions = new Queue<ScriptedRemoteSession>(new[] { firstSession, secondSession });
        var evidence = new RecordingEvidenceService();
        var identifications = new RecordingIdentificationRepository();
        var releaseDirectory = Path.Combine(Path.GetTempPath(), "EvaluationTool.Workflow.ChangedIdentity", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(releaseDirectory);
        try
        {
            var service = new CollectionWorkflowService(
                new BuiltinCommandPackCatalog(releaseDirectory),
                _ => sessions.Dequeue(),
                evidence,
                identifications);
            var initial = await service.RunAsync(
                CreateRequest(project, device, trust),
                new CountingProgress(),
                CancellationToken.None);
            var firstBatch = Assert.Single(identifications.PendingBatches);
            var staleCandidate = initial.DetectionCandidates.Single(candidate => candidate.Vendor == "kylin");

            var changed = await service.RunAsync(
                CreateRequest(project, device, trust, staleCandidate, firstBatch.BatchId),
                new CountingProgress(),
                CancellationToken.None);

            Assert.Equal(CollectionWorkflowOutcome.RequiresConfirmation, changed.Outcome);
            Assert.True(changed.PendingIdentificationBatchId.HasValue);
            Assert.NotEqual(firstBatch.BatchId, changed.PendingIdentificationBatchId.Value);
            Assert.Equal(2, identifications.PendingBatches.Count);
            Assert.Equal("ubuntu", Assert.Single(identifications.PendingBatches[1].Candidates).Vendor);
            var resolution = Assert.Single(identifications.Resolutions);
            Assert.Equal(firstBatch.BatchId, resolution.BatchId);
            Assert.Equal(PendingIdentificationResolution.SupersededByNewDetection, resolution.Resolution);
            Assert.Empty(identifications.Records);
            Assert.Empty(identifications.Tasks);
            Assert.Equal(
                new[] { "generic-linux-uname-a", "generic-linux-os-release" },
                secondSession.ExecutedIds);
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
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
        HostKeyTrust trust,
        DetectionCandidate? confirmedCandidate = null,
        Guid? pendingIdentificationBatchId = null)
    {
        return new CollectionWorkflowRequest(
            project,
            new CollectionDeviceSelection(
                device,
                isRequiredComponentAvailable: true,
                hostKeyTrust: trust),
            confirmedCandidate,
            pendingIdentificationBatchId);
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

    private static CommandOutput Success(string commandId, string output)
    {
        var now = new DateTimeOffset(2026, 7, 17, 0, 3, 0, TimeSpan.Zero);
        return new CommandOutput(commandId, output, string.Empty, 0, RemoteExecutionOutcome.Succeeded, null, now, now);
    }

    private static CommandOutput MissingOptional(string commandId)
    {
        var now = new DateTimeOffset(2026, 7, 17, 0, 3, 0, TimeSpan.Zero);
        return new CommandOutput(
            commandId,
            string.Empty,
            "command not found",
            127,
            RemoteExecutionOutcome.Failed,
            RemoteFailureCategory.ProcessFailed,
            now,
            now);
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

    private sealed class ScriptedRemoteSession : IRemoteSession, IDisposable
    {
        private readonly IReadOnlyDictionary<string, CommandOutput> outputs;

        internal ScriptedRemoteSession(IReadOnlyDictionary<string, CommandOutput> outputs)
        {
            this.outputs = outputs;
        }

        internal List<string> ExecutedIds { get; } = new List<string>();
        internal bool Disposed { get; private set; }

        public Task<CommandOutput> ExecuteAsync(CommandDefinition command, CancellationToken cancellationToken)
        {
            ExecutedIds.Add(command.Id);
            return Task.FromResult(outputs[command.Id]);
        }

        public void Dispose()
        {
            Disposed = true;
        }
    }

    private sealed class RecordingEvidenceService : ICollectionEvidenceService
    {
        internal List<string> SavedCommandIds { get; } = new List<string>();

        public Task<SavedCollectionEvidence> SaveAsync(
            ProjectRecord project,
            DeviceRecord device,
            string commandPackVersion,
            CommandDefinition command,
            CommandOutput output,
            CancellationToken cancellationToken = default)
        {
            SavedCommandIds.Add(command.Id);
            return Task.FromResult<SavedCollectionEvidence>(null!);
        }
    }

    private sealed class RecordingIdentificationRepository :
        IDeviceIdentificationRepository,
        IPendingDeviceIdentificationRepository,
        ICollectionTaskRepository
    {
        internal List<DeviceIdentificationRecord> Records { get; } = new List<DeviceIdentificationRecord>();
        internal List<PendingDeviceIdentificationBatch> PendingBatches { get; } =
            new List<PendingDeviceIdentificationBatch>();
        internal List<(Guid BatchId, PendingIdentificationResolution Resolution)> Resolutions { get; } =
            new List<(Guid BatchId, PendingIdentificationResolution Resolution)>();
        internal List<CollectionTaskRecord> Tasks { get; } = new List<CollectionTaskRecord>();
        internal Dictionary<CollectionTaskId, List<CollectionTaskEventRecord>> TaskEvents { get; } =
            new Dictionary<CollectionTaskId, List<CollectionTaskEventRecord>>();

        public Task<DeviceIdentificationRecord> AppendDeviceIdentificationAsync(
            DeviceId deviceId,
            DetectionCandidate candidate,
            bool wasUserConfirmed,
            string? confirmationSource,
            DateTimeOffset recordedAt,
            CancellationToken cancellationToken = default)
        {
            var record = new DeviceIdentificationRecord(
                deviceId,
                Records.Count + 1,
                candidate.Category,
                candidate.Vendor,
                candidate.ProductFamily,
                candidate.Model,
                candidate.Version,
                candidate.Evidence,
                candidate.Confidence,
                wasUserConfirmed,
                confirmationSource,
                recordedAt);
            Records.Add(record);
            return Task.FromResult(record);
        }

        public Task<DeviceIdentificationRecord?> GetLatestDeviceIdentificationAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<DeviceIdentificationRecord?>(
                Records.LastOrDefault(record => record.DeviceId.Equals(deviceId)));
        }

        public Task<IReadOnlyList<DeviceIdentificationRecord>> GetDeviceIdentificationHistoryAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<DeviceIdentificationRecord>>(
                Records.Where(record => record.DeviceId.Equals(deviceId)).ToArray());
        }

        public Task<PendingDeviceIdentificationBatch> AppendPendingDeviceIdentificationAsync(
            DeviceId deviceId,
            IReadOnlyList<DetectionCandidate> candidates,
            Guid? supersededBatchId,
            DateTimeOffset recordedAt,
            CancellationToken cancellationToken = default)
        {
            if (supersededBatchId.HasValue)
            {
                Resolutions.Add((
                    supersededBatchId.Value,
                    PendingIdentificationResolution.SupersededByNewDetection));
            }

            var batch = new PendingDeviceIdentificationBatch(
                Guid.NewGuid(), deviceId, PendingBatches.Count + 1, candidates, recordedAt);
            PendingBatches.Add(batch);
            return Task.FromResult(batch);
        }

        public Task<PendingDeviceIdentificationBatch?> GetLatestPendingDeviceIdentificationAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<PendingDeviceIdentificationBatch?>(
                PendingBatches.LastOrDefault(batch => batch.DeviceId.Equals(deviceId)));
        }

        public Task ResolvePendingDeviceIdentificationAsync(
            DeviceId deviceId,
            Guid batchId,
            PendingIdentificationResolution resolution,
            DateTimeOffset resolvedAt,
            CancellationToken cancellationToken = default)
        {
            Resolutions.Add((batchId, resolution));
            return Task.CompletedTask;
        }

        public Task<DeviceIdentificationRecord> CompletePendingDeviceIdentificationAsync(
            DeviceId deviceId,
            Guid batchId,
            DetectionCandidate confirmedCandidate,
            string confirmationSource,
            DateTimeOffset recordedAt,
            CancellationToken cancellationToken = default)
        {
            Resolutions.Add((batchId, PendingIdentificationResolution.RevalidatedAndCompleted));
            return AppendDeviceIdentificationAsync(
                deviceId,
                confirmedCandidate,
                true,
                confirmationSource,
                recordedAt,
                cancellationToken);
        }

        public Task<CollectionTaskRecord> CreateCollectionTaskAsync(
            CollectionTaskRecord task,
            CancellationToken cancellationToken = default)
        {
            Tasks.Add(task);
            TaskEvents.Add(task.Id, new List<CollectionTaskEventRecord>
            {
                new CollectionTaskEventRecord(
                    task.Id,
                    1,
                    CollectionTaskState.Ready,
                    null,
                    "TaskCreated",
                    task.CreatedAt)
            });
            return Task.FromResult(task);
        }

        public Task<CollectionTaskEventRecord> AppendCollectionTaskEventAsync(
            CollectionTaskId taskId,
            long expectedRevision,
            CollectionTaskState state,
            int? commandOrdinal,
            string eventCode,
            DateTimeOffset occurredAt,
            CancellationToken cancellationToken = default)
        {
            var events = TaskEvents[taskId];
            Assert.Equal(expectedRevision, events.Last().Revision);
            var record = new CollectionTaskEventRecord(
                taskId,
                expectedRevision + 1,
                state,
                commandOrdinal,
                eventCode,
                occurredAt);
            events.Add(record);
            return Task.FromResult(record);
        }

        public Task<IReadOnlyList<CollectionTaskRecord>> GetCollectionTasksAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<CollectionTaskRecord>>(
                Tasks.Where(task => task.ProjectId.Equals(projectId)).ToArray());
        }

        public Task<IReadOnlyList<CollectionTaskEventRecord>> GetCollectionTaskEventsAsync(
            CollectionTaskId taskId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<CollectionTaskEventRecord>>(TaskEvents[taskId].ToArray());
        }

        public Task<int> MarkInterruptedCollectionTasksAsync(
            DateTimeOffset interruptedAt,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }
    }
}
