using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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
                "postgresql@16-main.service loaded active running PostgreSQL Cluster 16-main\n"
                    + "tomcat9.service loaded active running Apache Tomcat 9"),
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
                result.Outcome == CollectionWorkflowOutcome.RequiresHostSoftwareConfirmation,
                "Actual outcome: " + result.Outcome + "; error: "
                + (result.Error == null ? "none" : JoinError(result.Error)));
            var candidate = Assert.Single(result.DatabaseCandidates);
            Assert.Equal("PostgreSQL", candidate.Product);
            Assert.Equal("16", candidate.Version);
            Assert.True(candidate.RequiresUserConfirmation);
            Assert.NotNull(result.PendingHostSoftwareBatchId);
            var middleware = Assert.Single(result.MiddlewareCandidates);
            Assert.Equal("Apache Tomcat", middleware.Product);
            Assert.Equal("9", middleware.Version);
            Assert.Equal(2, result.HostSoftwareCandidates.Count);
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
            var discoveryBatch = Assert.Single(identifications.HostSoftwareBatches);
            Assert.Equal(result.PendingHostSoftwareBatchId, discoveryBatch.BatchId);
            Assert.Equal(task.Id, discoveryBatch.CollectionTaskId);
            Assert.Equal(2, discoveryBatch.Candidates.Count);
            var storedDatabase = Assert.Single(
                discoveryBatch.Candidates,
                item => item.Category == HostSoftwareCategory.Database);
            Assert.Equal("PostgreSQL", storedDatabase.Product);
            Assert.Equal("16", storedDatabase.Version);
            var storedMiddleware = Assert.Single(
                discoveryBatch.Candidates,
                item => item.Category == HostSoftwareCategory.Middleware);
            Assert.Equal("Apache Tomcat", storedMiddleware.Product);
            Assert.Equal("9", storedMiddleware.Version);
            Assert.All(discoveryBatch.Candidates.SelectMany(item => item.Sources), source =>
            {
                Assert.Equal(task.Id, source.CollectionTaskId);
                Assert.Equal(new string('a', 64), source.RawOutputSha256);
            });
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
    public async Task Huawei_vrp_collection_requires_human_identity_confirmation_then_runs_only_fixed_read_only_pack()
    {
        var project = CreateProject();
        var device = CreateDevice(project, ConnectionProtocol.Ssh, TargetCategory.NetworkDevice, "192.0.2.60", "audit-user");
        var trust = CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        const string versionOutput = "Huawei Versatile Routing Platform Software\n"
            + "VRP (R) software, Version 8.200 (CloudEngine V200R023C00)";
        var firstSession = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["huawei-vrp-display-version"] = Success("huawei-vrp-display-version", versionOutput)
        });
        var secondSession = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["huawei-vrp-display-version"] = Success("huawei-vrp-display-version", versionOutput),
            ["huawei-vrp-display-aaa-configuration"] = Success(
                "huawei-vrp-display-aaa-configuration",
                "Administrator user default domain: default_admin\nLocal-user block retry-time: 3")
        });
        var sessions = new Queue<ScriptedRemoteSession>(new[] { firstSession, secondSession });
        var evidence = new RecordingEvidenceService();
        var identifications = new RecordingIdentificationRepository();
        var releaseDirectory = Path.Combine(Path.GetTempPath(), "EvaluationTool.Workflow.HuaweiVrp", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(releaseDirectory);
        try
        {
            var service = new CollectionWorkflowService(
                new BuiltinCommandPackCatalog(releaseDirectory),
                _ => sessions.Dequeue(),
                evidence,
                identifications);

            var detected = await service.RunAsync(
                CreateRequest(project, device, trust),
                new CountingProgress(),
                CancellationToken.None);

            Assert.Equal(CollectionWorkflowOutcome.RequiresConfirmation, detected.Outcome);
            var candidate = Assert.Single(detected.DetectionCandidates);
            Assert.Equal(TargetCategory.NetworkDevice, candidate.Category);
            Assert.Equal("Huawei", candidate.Vendor);
            Assert.Equal(0.85, candidate.Confidence);
            var pending = Assert.Single(identifications.PendingBatches);
            Assert.Equal(new[] { "huawei-vrp-display-version" }, firstSession.ExecutedIds);
            Assert.Empty(identifications.Tasks);

            var completed = await service.RunAsync(
                CreateRequest(project, device, trust, candidate, pending.BatchId),
                new CountingProgress(),
                CancellationToken.None);

            Assert.Equal(CollectionWorkflowOutcome.Completed, completed.Outcome);
            Assert.Equal(
                new[] { "huawei-vrp-display-version", "huawei-vrp-display-aaa-configuration" },
                secondSession.ExecutedIds);
            Assert.Equal(
                new[] { "huawei-vrp-display-aaa-configuration" },
                completed.CompletedCommands.Select(command => command.CommandId));
            var identification = Assert.Single(identifications.Records);
            Assert.True(identification.WasUserConfirmed);
            Assert.Equal("Huawei", identification.Vendor);
            var task = Assert.Single(identifications.Tasks);
            Assert.Equal(2, task.Commands.Count);
            Assert.All(task.Commands, command => Assert.Equal("huawei-vrp", command.CommandPackId));
            Assert.Equal(CollectionTaskState.Completed, identifications.TaskEvents[task.Id].Last().State);
            Assert.DoesNotContain(secondSession.ExecutedIds, command => command.StartsWith("generic-linux", StringComparison.Ordinal));
            Assert.DoesNotContain(secondSession.ExecutedIds, command => command.StartsWith("database-host-discovery", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task H3c_comware_collection_requires_human_confirmation_then_runs_only_password_policy_query()
    {
        var project = CreateProject();
        var device = CreateDevice(project, ConnectionProtocol.Ssh, TargetCategory.NetworkDevice, "192.0.2.63", "audit-user");
        var trust = CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        const string versionOutput = "H3C Comware Software, Version 7.1.070, Ess 6505\n"
            + "H3C S6850-56HF uptime is 0 weeks, 0 days, 3 hours, 43 minutes";
        var firstSession = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["h3c-comware-display-version"] = Success("h3c-comware-display-version", versionOutput)
        });
        var secondSession = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["h3c-comware-display-version"] = Success("h3c-comware-display-version", versionOutput),
            ["h3c-comware-display-password-control"] = Success(
                "h3c-comware-display-password-control",
                "Global password control configurations:\n Password aging: 90 days")
        });
        var sessions = new Queue<ScriptedRemoteSession>(new[] { firstSession, secondSession });
        var identifications = new RecordingIdentificationRepository();
        var releaseDirectory = Path.Combine(Path.GetTempPath(), "EvaluationTool.Workflow.H3cComware", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(releaseDirectory);
        try
        {
            var service = new CollectionWorkflowService(
                new BuiltinCommandPackCatalog(releaseDirectory),
                _ => sessions.Dequeue(),
                new RecordingEvidenceService(),
                identifications);
            var selection = new CollectionDeviceSelection(device, true, trust);

            var detected = await service.RunAsync(
                new CollectionWorkflowRequest(project, selection, CollectionAdapterId.H3cComware),
                new CountingProgress(),
                CancellationToken.None);

            Assert.Equal(CollectionWorkflowOutcome.RequiresConfirmation, detected.Outcome);
            var candidate = Assert.Single(detected.DetectionCandidates);
            Assert.Equal("H3C", candidate.Vendor);
            Assert.Equal("Comware", candidate.ProductFamily);
            Assert.Equal("7.1.070", candidate.Version);
            var pending = Assert.Single(identifications.PendingBatches);
            Assert.Equal(new[] { "h3c-comware-display-version" }, firstSession.ExecutedIds);

            var completed = await service.RunAsync(
                new CollectionWorkflowRequest(
                    project,
                    selection,
                    CollectionAdapterId.H3cComware,
                    candidate,
                    pending.BatchId),
                new CountingProgress(),
                CancellationToken.None);

            Assert.Equal(CollectionWorkflowOutcome.Completed, completed.Outcome);
            Assert.Equal(
                new[] { "h3c-comware-display-version", "h3c-comware-display-password-control" },
                secondSession.ExecutedIds);
            Assert.Equal(
                new[] { "h3c-comware-display-password-control" },
                completed.CompletedCommands.Select(command => command.CommandId));
            var task = Assert.Single(identifications.Tasks);
            Assert.All(task.Commands, command => Assert.Equal("h3c-comware", command.CommandPackId));
            Assert.DoesNotContain(secondSession.ExecutedIds, command => command.StartsWith("huawei-vrp", StringComparison.Ordinal));
            Assert.DoesNotContain(secondSession.ExecutedIds, command => command.StartsWith("generic-linux", StringComparison.Ordinal));
            Assert.DoesNotContain(secondSession.ExecutedIds, command => command.StartsWith("database-host-discovery", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task Windows_server_ssh_requires_human_confirmation_then_runs_only_account_policy_query()
    {
        var project = CreateProject();
        var device = CreateDevice(project, ConnectionProtocol.Ssh, TargetCategory.Server, "192.0.2.64", "audit-user");
        var trust = CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        const string productOutput = "ProductName    REG_SZ    Windows Server 2022 Standard";
        const string buildOutput = "CurrentBuildNumber    REG_SZ    20348";
        var firstSession = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["windows-server-ssh-product-name"] = Success("windows-server-ssh-product-name", productOutput),
            ["windows-server-ssh-build-number"] = Success("windows-server-ssh-build-number", buildOutput)
        });
        var secondSession = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["windows-server-ssh-product-name"] = Success("windows-server-ssh-product-name", productOutput),
            ["windows-server-ssh-build-number"] = Success("windows-server-ssh-build-number", buildOutput),
            ["windows-server-ssh-account-policy"] = Success(
                "windows-server-ssh-account-policy",
                "Minimum password length: 14\nLockout threshold: 5")
        });
        var sessions = new Queue<ScriptedRemoteSession>(new[] { firstSession, secondSession });
        var identifications = new RecordingIdentificationRepository();
        var releaseDirectory = Path.Combine(Path.GetTempPath(), "EvaluationTool.Workflow.WindowsServer", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(releaseDirectory);
        try
        {
            var service = new CollectionWorkflowService(
                new BuiltinCommandPackCatalog(releaseDirectory),
                _ => sessions.Dequeue(),
                new RecordingEvidenceService(),
                identifications);
            var selection = new CollectionDeviceSelection(device, true, trust);

            var detected = await service.RunAsync(
                new CollectionWorkflowRequest(project, selection, CollectionAdapterId.WindowsServerSsh),
                new CountingProgress(),
                CancellationToken.None);

            Assert.Equal(CollectionWorkflowOutcome.RequiresConfirmation, detected.Outcome);
            var candidate = Assert.Single(detected.DetectionCandidates);
            Assert.Equal("Microsoft", candidate.Vendor);
            Assert.Equal("Windows Server", candidate.ProductFamily);
            Assert.Equal("2022", candidate.Version);
            Assert.Equal("Standard", candidate.Model);
            var pending = Assert.Single(identifications.PendingBatches);
            Assert.Equal(
                new[] { "windows-server-ssh-product-name", "windows-server-ssh-build-number" },
                firstSession.ExecutedIds);
            Assert.Empty(identifications.Tasks);

            var completed = await service.RunAsync(
                new CollectionWorkflowRequest(
                    project,
                    selection,
                    CollectionAdapterId.WindowsServerSsh,
                    candidate,
                    pending.BatchId),
                new CountingProgress(),
                CancellationToken.None);

            Assert.Equal(CollectionWorkflowOutcome.Completed, completed.Outcome);
            Assert.Equal(
                new[]
                {
                    "windows-server-ssh-product-name",
                    "windows-server-ssh-build-number",
                    "windows-server-ssh-account-policy"
                },
                secondSession.ExecutedIds);
            Assert.Equal(
                new[] { "windows-server-ssh-account-policy" },
                completed.CompletedCommands.Select(command => command.CommandId));
            var identification = Assert.Single(identifications.Records);
            Assert.True(identification.WasUserConfirmed);
            Assert.Equal("Microsoft", identification.Vendor);
            var task = Assert.Single(identifications.Tasks);
            Assert.All(task.Commands, command => Assert.Equal("windows-server-ssh", command.CommandPackId));
            Assert.DoesNotContain(secondSession.ExecutedIds, command => command.StartsWith("generic-linux", StringComparison.Ordinal));
            Assert.DoesNotContain(secondSession.ExecutedIds, command => command.StartsWith("database-host-discovery", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task Windows_adapter_rejects_client_identity_without_empty_confirmation_dead_end()
    {
        var project = CreateProject();
        var device = CreateDevice(project, ConnectionProtocol.Ssh, TargetCategory.Server, "192.0.2.65", "audit-user");
        var trust = CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        var session = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["windows-server-ssh-product-name"] = Success(
                "windows-server-ssh-product-name",
                "ProductName    REG_SZ    Windows 11 Enterprise"),
            ["windows-server-ssh-build-number"] = Success(
                "windows-server-ssh-build-number",
                "CurrentBuildNumber    REG_SZ    26100")
        });
        var identifications = new RecordingIdentificationRepository();
        var releaseDirectory = Path.Combine(Path.GetTempPath(), "EvaluationTool.Workflow.NonWindowsServer", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(releaseDirectory);
        try
        {
            var service = new CollectionWorkflowService(
                new BuiltinCommandPackCatalog(releaseDirectory),
                _ => session,
                new RecordingEvidenceService(),
                identifications);

            var result = await service.RunAsync(
                new CollectionWorkflowRequest(
                    project,
                    new CollectionDeviceSelection(device, true, trust),
                    CollectionAdapterId.WindowsServerSsh),
                new CountingProgress(),
                CancellationToken.None);

            Assert.Equal(CollectionWorkflowOutcome.Failed, result.Outcome);
            Assert.Equal("WindowsServerIdentityNotDetected", result.Error!.TechnicalDetails);
            Assert.Equal(
                new[] { "windows-server-ssh-product-name", "windows-server-ssh-build-number" },
                session.ExecutedIds);
            Assert.Empty(identifications.PendingBatches);
            Assert.Empty(identifications.Tasks);
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task Network_device_without_matching_adapter_is_rejected_before_session_creation()
    {
        var project = CreateProject();
        var device = CreateDevice(project, ConnectionProtocol.Ssh, TargetCategory.NetworkDevice, "192.0.2.62", "audit-user");
        var trust = CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        var sessionCreated = false;
        var service = new CollectionWorkflowService(
            new BuiltinCommandPackCatalog(),
            _ =>
            {
                sessionCreated = true;
                throw new InvalidOperationException("不应创建连接会话");
            },
            new RecordingEvidenceService());

        var result = await service.RunAsync(
            new CollectionWorkflowRequest(
                project,
                new CollectionDeviceSelection(device, true, trust),
                CollectionAdapterId.GenericLinux),
            new CountingProgress(),
            CancellationToken.None);

        Assert.Equal(CollectionWorkflowOutcome.Failed, result.Outcome);
        Assert.Equal("CollectionAdapterTargetMismatch", result.Error!.TechnicalDetails);
        Assert.False(sessionCreated);
    }

    [Fact]
    public async Task Non_huawei_network_device_stops_after_version_probe_without_aaa_collection_or_pending_batch()
    {
        var project = CreateProject();
        var device = CreateDevice(project, ConnectionProtocol.Ssh, TargetCategory.NetworkDevice, "192.0.2.61", "audit-user");
        var trust = CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        var session = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["huawei-vrp-display-version"] = Success(
                "huawei-vrp-display-version",
                "H3C Comware Software, Version 7.1.070")
        });
        var evidence = new RecordingEvidenceService();
        var identifications = new RecordingIdentificationRepository();
        var releaseDirectory = Path.Combine(Path.GetTempPath(), "EvaluationTool.Workflow.NonHuawei", Guid.NewGuid().ToString("N"));
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

            Assert.Equal(CollectionWorkflowOutcome.Failed, result.Outcome);
            Assert.Equal("HuaweiVrpIdentityNotDetected", result.Error!.TechnicalDetails);
            Assert.Equal(new[] { "huawei-vrp-display-version" }, session.ExecutedIds);
            Assert.DoesNotContain("huawei-vrp-display-aaa-configuration", session.ExecutedIds);
            Assert.Empty(identifications.PendingBatches);
            Assert.Empty(identifications.Records);
            Assert.Empty(identifications.Tasks);
        }
        finally
        {
            Directory.Delete(releaseDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task Current_project_lock_replaces_only_the_collection_pack_and_is_snapshotted_in_the_task()
    {
        var project = CreateProject();
        var device = CreateDevice(project, ConnectionProtocol.Ssh, TargetCategory.Server, "192.0.2.49", "audit-user");
        var trust = CreateTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        var customPack = LoadCustomGenericLinuxPack();
        var session = new ScriptedRemoteSession(new Dictionary<string, CommandOutput>(StringComparer.Ordinal)
        {
            ["generic-linux-uname-a"] = Success("generic-linux-uname-a", "Linux audit-host 6.8.0 x86_64 GNU/Linux"),
            ["generic-linux-os-release"] = Success("generic-linux-os-release", "ID=ubuntu\nVERSION_ID=24.04"),
            ["custom-linux-hostname"] = Success("custom-linux-hostname", "audit-host"),
            ["database-host-discovery-linux-processes"] = Success("database-host-discovery-linux-processes", string.Empty),
            ["database-host-discovery-linux-services"] = Success("database-host-discovery-linux-services", string.Empty),
            ["database-host-discovery-linux-docker-containers"] = MissingOptional("database-host-discovery-linux-docker-containers"),
            ["database-host-discovery-linux-podman-containers"] = MissingOptional("database-host-discovery-linux-podman-containers")
        });
        var evidence = new RecordingEvidenceService();
        var identifications = new RecordingIdentificationRepository();
        var releaseDirectory = Path.Combine(Path.GetTempPath(), "EvaluationTool.Workflow.LockedPack", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(releaseDirectory);
        try
        {
            var service = new CollectionWorkflowService(
                new BuiltinCommandPackCatalog(releaseDirectory),
                _ => session,
                evidence,
                identifications,
                null,
                new FixedCommandPackReleaseService(customPack));

            var result = await service.RunAsync(
                CreateRequest(project, device, trust),
                new CountingProgress(),
                CancellationToken.None);

            Assert.Equal(CollectionWorkflowOutcome.Completed, result.Outcome);
            Assert.Contains("custom-linux-hostname", session.ExecutedIds);
            Assert.DoesNotContain("generic-linux-hostname", session.ExecutedIds);
            Assert.DoesNotContain("generic-linux-login-defs", session.ExecutedIds);
            var task = Assert.Single(identifications.Tasks);
            var snapshot = Assert.Single(task.Commands, item => item.CommandId == "custom-linux-hostname");
            Assert.Equal(customPack.Id, snapshot.CommandPackId);
            Assert.Equal(customPack.Version, snapshot.CommandPackVersion);
            Assert.Equal(customPack.Sha256, snapshot.CommandPackSha256);
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
            device.Category == TargetCategory.NetworkDevice
                ? CollectionAdapterId.HuaweiVrp
                : CollectionAdapterId.GenericLinux,
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

    private static CommandPack LoadCustomGenericLinuxPack()
    {
        var json = "{"
            + "\"id\":\"generic-linux\",\"name\":\"项目 Linux 命令\",\"version\":\"2.0.0\","
            + "\"officialSource\":\"https://vendor.example/linux\",\"commands\":[{"
            + "\"id\":\"custom-linux-hostname\",\"title\":\"读取主机名\",\"targetCategory\":\"Server\","
            + "\"commandText\":\"hostname\",\"verificationStatus\":\"Verified\",\"isReadOnly\":true,"
            + "\"vendor\":null,\"productFamily\":null,\"minimumVersion\":\"1.0\",\"maximumVersion\":\"99.0\","
            + "\"checkItem\":\"SYSTEM_IDENTITY\",\"modelRange\":\"*\",\"accountRequirement\":\"只读账户\","
            + "\"riskLevel\":\"Low\",\"timeoutSeconds\":30,\"pagingBehavior\":\"NotApplicable\","
            + "\"resultDescription\":\"主机名\",\"verificationDate\":\"2025-01-01\","
            + "\"officialSource\":\"https://vendor.example/hostname\",\"optional\":false}]}";
        var bytes = Encoding.UTF8.GetBytes(json);
        using (var algorithm = SHA256.Create())
        {
            var hash = string.Concat(algorithm.ComputeHash(bytes).Select(value => value.ToString("x2")));
            return new CommandPackLoader().Load(bytes, hash);
        }
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

    private sealed class FixedCommandPackReleaseService : ICommandPackReleaseService
    {
        private readonly CommandPack pack;

        public FixedCommandPackReleaseService(CommandPack pack)
        {
            this.pack = pack;
        }

        public Task<CommandPackReleaseSnapshot> LoadAsync(
            ProjectId? projectId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new CommandPackReleaseSnapshot(
                Array.Empty<PublishedCommandPackRecord>(),
                Array.Empty<ProjectCommandPackLockRecord>()));
        }

        public Task<PublishedCommandPackRecord> ReviewAndPublishAsync(
            Guid draftId,
            string reviewedBy,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<ProjectCommandPackLockRecord> LockToProjectAsync(
            ProjectId projectId,
            string packId,
            string version,
            string source,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<CommandPack?> LoadCurrentProjectPackAsync(
            ProjectId projectId,
            string packId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<CommandPack?>(
                string.Equals(pack.Id, packId, StringComparison.Ordinal) ? pack : null);
        }
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
            const string hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            const string imagePath = "screenshots\\page-001.png";
            var execution = new ExecutionRecord(
                project.Id.ToString(),
                device.Id.ToString(),
                device.Protocol,
                commandPackVersion,
                command.Id,
                command.CommandText,
                output.StartedAt,
                output.CompletedAt,
                ExecutionStatus.Succeeded,
                output.ExitCode,
                "raw\\output.txt",
                hash,
                new[] { imagePath },
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    [imagePath] = hash
                },
                null);
            return Task.FromResult(new SavedCollectionEvidence(
                "batch",
                "manifest.json",
                execution,
                new[] { imagePath },
                true));
        }
    }

    private sealed class RecordingIdentificationRepository :
        IDeviceIdentificationRepository,
        IPendingDeviceIdentificationRepository,
        ICollectionTaskRepository,
        IHostSoftwareDiscoveryRepository
    {
        internal List<DeviceIdentificationRecord> Records { get; } = new List<DeviceIdentificationRecord>();
        internal List<PendingDeviceIdentificationBatch> PendingBatches { get; } =
            new List<PendingDeviceIdentificationBatch>();
        internal List<(Guid BatchId, PendingIdentificationResolution Resolution)> Resolutions { get; } =
            new List<(Guid BatchId, PendingIdentificationResolution Resolution)>();
        internal List<CollectionTaskRecord> Tasks { get; } = new List<CollectionTaskRecord>();
        internal Dictionary<CollectionTaskId, List<CollectionTaskEventRecord>> TaskEvents { get; } =
            new Dictionary<CollectionTaskId, List<CollectionTaskEventRecord>>();
        internal List<HostSoftwareDiscoveryBatchRecord> HostSoftwareBatches { get; } =
            new List<HostSoftwareDiscoveryBatchRecord>();
        internal List<HostSoftwareCandidateDecisionRecord> HostSoftwareDecisions { get; } =
            new List<HostSoftwareCandidateDecisionRecord>();

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

        public Task<HostSoftwareDiscoveryBatchRecord> AppendHostSoftwareDiscoveryBatchAsync(
            ProjectId projectId,
            DeviceId deviceId,
            CollectionTaskId collectionTaskId,
            IReadOnlyList<HostSoftwareDiscoveryCandidateInput> candidates,
            string discoverySource,
            DateTimeOffset recordedAt,
            CancellationToken cancellationToken = default)
        {
            var task = Assert.Single(Tasks, item => item.Id.Equals(collectionTaskId));
            var batchId = Guid.NewGuid();
            var previous = HostSoftwareBatches.LastOrDefault(item => item.DeviceId.Equals(deviceId));
            var records = candidates.Select((candidate, candidateOrdinal) =>
            {
                var candidateId = Guid.NewGuid();
                var sources = candidate.Sources.Select((source, sourceOrdinal) =>
                {
                    var command = Assert.Single(
                        task.Commands,
                        item => string.Equals(item.CommandId, source.SourceCommandId, StringComparison.Ordinal));
                    return new HostSoftwareDiscoveryEvidenceRecord(
                        Guid.NewGuid(),
                        candidateId,
                        sourceOrdinal,
                        collectionTaskId,
                        command.Ordinal,
                        source.Kind,
                        source.SourceCommandId,
                        source.Excerpt,
                        source.RawOutputSha256);
                }).ToArray();
                return new HostSoftwareDiscoveryCandidateRecord(
                    candidateId,
                    batchId,
                    candidateOrdinal,
                    candidate.Category,
                    candidate.Product,
                    candidate.Version,
                    candidate.InstallationType,
                    candidate.InstanceName,
                    candidate.PortEvidence,
                    candidate.Confidence,
                    sources);
            }).ToArray();
            var batch = new HostSoftwareDiscoveryBatchRecord(
                batchId,
                projectId,
                deviceId,
                collectionTaskId,
                previous == null ? 1 : previous.Revision + 1,
                previous?.BatchId,
                discoverySource,
                records,
                recordedAt);
            HostSoftwareBatches.Add(batch);
            return Task.FromResult(batch);
        }

        public Task<HostSoftwareDiscoveryBatchRecord?> GetLatestHostSoftwareDiscoveryBatchAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<HostSoftwareDiscoveryBatchRecord?>(
                HostSoftwareBatches.LastOrDefault(item => item.DeviceId.Equals(deviceId)));
        }

        public Task<PendingHostSoftwareDiscoveryBatchRecord?> GetLatestPendingHostSoftwareDiscoveryBatchAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            var batch = HostSoftwareBatches.LastOrDefault(item => item.DeviceId.Equals(deviceId));
            if (batch == null)
            {
                return Task.FromResult<PendingHostSoftwareDiscoveryBatchRecord?>(null);
            }

            var decided = new HashSet<Guid>(HostSoftwareDecisions.Select(item => item.CandidateId));
            var pending = batch.Candidates.Where(item => !decided.Contains(item.CandidateId)).ToArray();
            return Task.FromResult<PendingHostSoftwareDiscoveryBatchRecord?>(
                pending.Length == 0 ? null : new PendingHostSoftwareDiscoveryBatchRecord(batch, pending));
        }

        public Task<IReadOnlyList<HostSoftwareDiscoveryBatchRecord>> GetHostSoftwareDiscoveryHistoryAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<HostSoftwareDiscoveryBatchRecord>>(
                HostSoftwareBatches.Where(item => item.DeviceId.Equals(deviceId)).ToArray());
        }

        public Task<HostSoftwareCandidateDecisionRecord> AppendHostSoftwareCandidateDecisionAsync(
            Guid candidateId,
            HostSoftwareCandidateDecision decision,
            string decidedBy,
            string decisionSource,
            string? reason,
            DateTimeOffset decidedAt,
            CancellationToken cancellationToken = default)
        {
            var record = new HostSoftwareCandidateDecisionRecord(
                Guid.NewGuid(), candidateId, decision, decidedBy, decisionSource, reason, decidedAt);
            HostSoftwareDecisions.Add(record);
            return Task.FromResult(record);
        }

        public Task<IReadOnlyList<HostSoftwareCandidateDecisionRecord>> GetHostSoftwareCandidateDecisionsAsync(
            Guid batchId,
            CancellationToken cancellationToken = default)
        {
            var candidateIds = new HashSet<Guid>(HostSoftwareBatches
                .Where(item => item.BatchId == batchId)
                .SelectMany(item => item.Candidates)
                .Select(item => item.CandidateId));
            return Task.FromResult<IReadOnlyList<HostSoftwareCandidateDecisionRecord>>(
                HostSoftwareDecisions.Where(item => candidateIds.Contains(item.CandidateId)).ToArray());
        }
    }
}
