using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class EvidenceCenterServiceTests
{
    private const string RawHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string ImageHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string OtherHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    [Fact]
    public async Task Load_combines_repository_indexes_without_opening_evidence_files()
    {
        var projectId = ProjectId.New();
        var deviceId = DeviceId.New();
        var earlier = CreateExecution(
            projectId,
            deviceId,
            "earlier",
            DateTimeOffset.Parse("2026-07-17T01:00:00Z"));
        var later = CreateExecution(
            projectId,
            deviceId,
            "later",
            DateTimeOffset.Parse("2026-07-17T02:00:00Z"));
        var repository = new FakeProjectRepository
        {
            Executions = new[] { earlier, later },
            EvidenceFiles = CreateEvidenceFiles(projectId, deviceId, earlier)
                .Concat(CreateEvidenceFiles(projectId, deviceId, later))
                .ToArray(),
            Devices = new[] { CreateDevice(projectId, deviceId, "Linux服务器甲") },
            DatabaseConfirmations = new[]
            {
                CreateDatabaseConfirmation(projectId, deviceId, "PostgreSQL", "16.3")
            }
        };
        var service = new EvidenceCenterService(repository);

        var snapshot = await service.LoadAsync(projectId);

        Assert.Equal(projectId, snapshot.ProjectId);
        Assert.Equal(new[] { "later", "earlier" }, snapshot.Items.Select(item => item.CommandId));
        Assert.All(snapshot.Items, item => Assert.Equal(EvidenceShaStatus.Complete, item.ShaStatus));
        var item = snapshot.Items[0];
        Assert.Equal(ExecutionStatus.Succeeded, item.ExecutionStatus);
        Assert.Equal("Linux服务器甲", item.DeviceName);
        Assert.Equal("成功", item.ExecutionStatusText);
        Assert.Equal(later.RawOutputPath, item.RawOutputPath);
        Assert.Equal(later.RawOutputPath, item.RawOutputPathText);
        Assert.Equal(later.EvidenceImagePaths, item.EvidenceImagePaths);
        Assert.Equal(1, item.ScreenshotCount);
        Assert.Equal("1 张", item.ScreenshotCountText);
        Assert.Equal("索引完整（未复核文件）", item.ShaStatusText);
        var confirmation = Assert.Single(snapshot.DatabaseConfirmations);
        Assert.Equal("Linux服务器甲", confirmation.DeviceName);
        Assert.Equal("PostgreSQL", confirmation.Product);
        Assert.Equal("16.3", confirmation.VersionText);
        Assert.Equal("本机服务", confirmation.InstallationTypeText);
        Assert.Equal("5432/tcp", confirmation.PortEvidenceText);
        Assert.Equal("只读进程和服务元数据", confirmation.DetectionEvidence);
        Assert.Equal("测评人员人工确认", confirmation.ConfirmationSource);
        Assert.Equal(
            confirmation.ConfirmedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz"),
            confirmation.ConfirmedAtText);
        Assert.Equal(1, repository.ExecutionQueryCount);
        Assert.Equal(1, repository.EvidenceQueryCount);
        Assert.Equal(1, repository.DeviceQueryCount);
        Assert.Equal(1, repository.DatabaseConfirmationQueryCount);
        Assert.Equal(1, repository.HostSoftwareHistoryQueryCount);
        Assert.Equal(projectId, repository.RequestedProjectId);
    }

    [Fact]
    public async Task Host_software_audit_includes_all_decision_states_across_devices_in_stable_order()
    {
        var projectId = ProjectId.New();
        var deviceA = CreateDevice(projectId, DeviceId.New(), "设备 A");
        var deviceB = CreateDevice(projectId, DeviceId.New(), "设备 B");
        var earlierAt = DateTimeOffset.Parse("2026-07-17T08:00:00Z");
        var latestAt = DateTimeOffset.Parse("2026-07-17T09:00:00Z");
        var supersededBatch = CreateHostSoftwareBatch(
            projectId,
            deviceB.Id,
            1,
            null,
            earlierAt,
            (HostSoftwareCategory.Database, "PostgreSQL", "15", "postgresql.service"));
        var currentBatch = CreateHostSoftwareBatch(
            projectId,
            deviceB.Id,
            2,
            supersededBatch.BatchId,
            latestAt,
            (HostSoftwareCategory.Database, "MySQL", "8.0", "mysqld.service"),
            (HostSoftwareCategory.Middleware, "Apache Tomcat", "9.0", "tomcat.service"));
        var rejectedBatch = CreateHostSoftwareBatch(
            projectId,
            deviceA.Id,
            1,
            null,
            latestAt,
            (HostSoftwareCategory.Middleware, "Nginx", "1.24", "nginx.service"));
        var repository = new FakeProjectRepository
        {
            Devices = new[] { deviceB, deviceA },
            HostSoftwareHistories = new[] { currentBatch, supersededBatch, rejectedBatch },
            HostSoftwareDecisions = new Dictionary<Guid, IReadOnlyList<HostSoftwareCandidateDecisionRecord>>
            {
                [supersededBatch.BatchId] = new[]
                {
                    CreateHostSoftwareDecision(
                        supersededBatch.Candidates[0],
                        HostSoftwareCandidateDecision.Superseded,
                        "系统",
                        "new-discovery-batch",
                        "已由修订 2 的新发现批次取代",
                        latestAt)
                },
                [currentBatch.BatchId] = new[]
                {
                    CreateHostSoftwareDecision(
                        currentBatch.Candidates[0],
                        HostSoftwareCandidateDecision.Confirmed,
                        "CONTOSO\\assessor",
                        "evidence-center",
                        null,
                        latestAt.AddMinutes(2))
                },
                [rejectedBatch.BatchId] = new[]
                {
                    CreateHostSoftwareDecision(
                        rejectedBatch.Candidates[0],
                        HostSoftwareCandidateDecision.Rejected,
                        "CONTOSO\\reviewer",
                        "evidence-center",
                        "客户确认该服务属于其他业务",
                        latestAt.AddMinutes(1))
                }
            }
        };

        var snapshot = await new EvidenceCenterService(repository).LoadAsync(projectId);

        Assert.Equal(
            new[] { "Nginx", "MySQL", "Apache Tomcat", "PostgreSQL" },
            snapshot.HostSoftwareDiscoveries.Select(item => item.Product));
        Assert.Equal(
            new[]
            {
                HostSoftwareAuditDecisionStatus.Rejected,
                HostSoftwareAuditDecisionStatus.Confirmed,
                HostSoftwareAuditDecisionStatus.Pending,
                HostSoftwareAuditDecisionStatus.Superseded
            },
            snapshot.HostSoftwareDiscoveries.Select(item => item.DecisionStatus));

        var rejected = snapshot.HostSoftwareDiscoveries[0];
        Assert.Equal("设备 A", rejected.DeviceName);
        Assert.Equal(1, rejected.BatchRevision);
        Assert.Equal(latestAt, rejected.BatchRecordedAt);
        Assert.Equal(HostSoftwareCategory.Middleware, rejected.Category);
        Assert.Equal("1.24", rejected.Version);
        Assert.Equal(HostSoftwareInstallationType.LocalService, rejected.InstallationType);
        Assert.Equal("nginx.service", rejected.InstanceName);
        Assert.Equal("未发现", rejected.PortEvidenceText);
        Assert.Equal(0.91, rejected.Confidence);
        Assert.Equal("服务：nginx.service active running", rejected.EvidenceSummary);
        Assert.Equal("CONTOSO\\reviewer", rejected.DecidedBy);
        Assert.Equal("已排除", rejected.DecisionStatusText);
        Assert.Equal("evidence-center", rejected.DecisionSource);
        Assert.Equal("客户确认该服务属于其他业务", rejected.DecisionReason);
        Assert.Equal(latestAt.AddMinutes(1), rejected.DecidedAt);

        var pending = snapshot.HostSoftwareDiscoveries[2];
        Assert.Equal("设备 B", pending.DeviceName);
        Assert.Equal(2, pending.BatchRevision);
        Assert.Null(pending.DecidedBy);
        Assert.Null(pending.DecisionSource);
        Assert.Null(pending.DecisionReason);
        Assert.Null(pending.DecidedAt);

        var superseded = snapshot.HostSoftwareDiscoveries[3];
        Assert.Equal("系统", superseded.DecidedBy);
        Assert.Equal("new-discovery-batch", superseded.DecisionSource);
        Assert.Contains("修订 2", superseded.DecisionReason, StringComparison.Ordinal);
        Assert.Equal(2, repository.HostSoftwareHistoryQueryCount);
        Assert.Equal(3, repository.HostSoftwareDecisionQueryCount);
    }

    [Fact]
    public async Task Sha_status_reports_missing_mismatch_and_not_available_from_index_metadata_only()
    {
        var projectId = ProjectId.New();
        var deviceId = DeviceId.New();
        var missing = CreateExecution(projectId, deviceId, "missing", DateTimeOffset.UtcNow.AddMinutes(-3));
        var mismatch = CreateExecution(projectId, deviceId, "mismatch", DateTimeOffset.UtcNow.AddMinutes(-2));
        var noEvidence = CreateFailedExecution(projectId, deviceId, "none", DateTimeOffset.UtcNow.AddMinutes(-1));
        var mismatchFiles = CreateEvidenceFiles(projectId, deviceId, mismatch).ToArray();
        mismatchFiles[0] = new EvidenceFileRecord(
            projectId,
            deviceId,
            mismatchFiles[0].RelativePath,
            OtherHash,
            EvidenceFileKind.RawOutput,
            mismatchFiles[0].Ordinal,
            mismatchFiles[0].CreatedAt);
        var repository = new FakeProjectRepository
        {
            Executions = new[] { missing, mismatch, noEvidence },
            EvidenceFiles = mismatchFiles
        };

        var snapshot = await new EvidenceCenterService(repository).LoadAsync(projectId);

        Assert.Equal(EvidenceShaStatus.Missing,
            snapshot.Items.Single(item => item.CommandId == "missing").ShaStatus);
        Assert.Equal(EvidenceShaStatus.Mismatch,
            snapshot.Items.Single(item => item.CommandId == "mismatch").ShaStatus);
        var emptyItem = snapshot.Items.Single(item => item.CommandId == "none");
        Assert.Equal(EvidenceShaStatus.NotAvailable, emptyItem.ShaStatus);
        Assert.Equal("未生成", emptyItem.RawOutputPathText);
        Assert.Equal("暂无 SHA", emptyItem.ShaStatusText);
    }

    [Fact]
    public async Task Repository_error_becomes_structured_sanitized_failure()
    {
        var repository = new FakeProjectRepository
        {
            ExecutionError = new InvalidOperationException(@"secret C:\customer\evidence.db")
        };
        var service = new EvidenceCenterService(repository);

        var error = await Assert.ThrowsAsync<EvidenceCenterException>(
            () => service.LoadAsync(ProjectId.New()));

        Assert.Equal(EvidenceCenterFailure.IndexUnavailable, error.Failure);
        Assert.Contains("证据索引", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("secret", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("customer", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(error.InnerException);
        Assert.Equal(0, repository.EvidenceQueryCount);
    }

    [Fact]
    public async Task Confirmation_audit_error_cannot_be_silently_hidden()
    {
        var repository = new FakeProjectRepository
        {
            DatabaseConfirmationError = new InvalidOperationException(@"secret C:\customer\audit.db")
        };

        var error = await Assert.ThrowsAsync<EvidenceCenterException>(
            () => new EvidenceCenterService(repository).LoadAsync(ProjectId.New()));

        Assert.Equal(EvidenceCenterFailure.IndexUnavailable, error.Failure);
        Assert.Contains("证据索引", error.Message, StringComparison.Ordinal);
        Assert.Equal(1, repository.DatabaseConfirmationQueryCount);
        Assert.DoesNotContain("secret", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Invalid_project_is_rejected_before_repository_access()
    {
        var repository = new FakeProjectRepository();
        var service = new EvidenceCenterService(repository);

        var error = await Assert.ThrowsAsync<EvidenceCenterException>(
            () => service.LoadAsync(default(ProjectId)));

        Assert.Equal(EvidenceCenterFailure.InvalidProject, error.Failure);
        Assert.Equal(0, repository.ExecutionQueryCount);
        Assert.Equal(0, repository.EvidenceQueryCount);
    }

    [Fact]
    public async Task Cancellation_is_preserved_instead_of_converted_to_failure()
    {
        var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var repository = new FakeProjectRepository();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new EvidenceCenterService(repository).LoadAsync(ProjectId.New(), cancellation.Token));
    }

    [Fact]
    public async Task Verify_reads_contained_files_and_reports_verified_missing_and_mismatch()
    {
        var root = Path.Combine(Path.GetTempPath(), "AssessmentTool-EvidenceVerify-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var projectId = ProjectId.New();
            var deviceId = DeviceId.New();
            var rawPath = @"设备甲\批次甲\原始输出.txt";
            var imagePath = @"设备甲\批次甲\证据_001.png";
            var rawBytes = new byte[] { 1, 2, 3, 4 };
            var imageBytes = new byte[] { 5, 6, 7, 8 };
            WriteRelative(root, rawPath, rawBytes);
            WriteRelative(root, imagePath, imageBytes);
            var execution = CreateExecutionWithHashes(
                projectId,
                deviceId,
                rawPath,
                Hash(rawBytes),
                imagePath,
                Hash(imageBytes));
            var repository = new FakeProjectRepository
            {
                Executions = new[] { execution },
                EvidenceFiles = CreateEvidenceFiles(projectId, deviceId, execution).ToArray(),
                Projects = new[] { new ProjectRecord(projectId, "客户", "项目", root, DateTimeOffset.UtcNow) }
            };
            var service = new EvidenceCenterService(repository);

            var verified = await service.VerifyAsync(projectId);
            Assert.Equal(EvidenceShaStatus.Verified, Assert.Single(verified.Items).ShaStatus);
            Assert.Equal("文件与索引 SHA-256 一致", verified.Items[0].ShaStatusText);

            File.WriteAllBytes(ResolveRelative(root, imagePath), new byte[] { 9, 9, 9 });
            var mismatch = await service.VerifyAsync(projectId);
            Assert.Equal(EvidenceShaStatus.Mismatch, Assert.Single(mismatch.Items).ShaStatus);

            File.Delete(ResolveRelative(root, rawPath));
            var missing = await service.VerifyAsync(projectId);
            Assert.Equal(EvidenceShaStatus.Missing, Assert.Single(missing.Items).ShaStatus);
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task Verify_rejects_project_missing_from_persisted_repository()
    {
        var projectId = ProjectId.New();
        var repository = new FakeProjectRepository();

        var error = await Assert.ThrowsAsync<EvidenceCenterException>(
            () => new EvidenceCenterService(repository).VerifyAsync(projectId));

        Assert.Equal(EvidenceCenterFailure.InvalidProject, error.Failure);
        Assert.DoesNotContain("path", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static ExecutionRecord CreateExecution(
        ProjectId projectId,
        DeviceId deviceId,
        string commandId,
        DateTimeOffset startedAt)
    {
        var rawPath = @"设备\" + commandId + @"\原始输出.txt";
        var imagePath = @"设备\" + commandId + @"\证据-001.png";
        return new ExecutionRecord(
            projectId.ToString(),
            deviceId.ToString(),
            ConnectionProtocol.Ssh,
            "1.0.0",
            commandId,
            "hostname",
            startedAt,
            startedAt.AddSeconds(1),
            ExecutionStatus.Succeeded,
            0,
            rawPath,
            RawHash,
            new[] { imagePath },
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [imagePath] = ImageHash
            },
            null);
    }

    private static ExecutionRecord CreateExecutionWithHashes(
        ProjectId projectId,
        DeviceId deviceId,
        string rawPath,
        string rawHash,
        string imagePath,
        string imageHash)
    {
        var startedAt = DateTimeOffset.UtcNow;
        return new ExecutionRecord(
            projectId.ToString(),
            deviceId.ToString(),
            ConnectionProtocol.Ssh,
            "1.0.0",
            "verify",
            "hostname",
            startedAt,
            startedAt.AddSeconds(1),
            ExecutionStatus.Succeeded,
            0,
            rawPath,
            rawHash,
            new[] { imagePath },
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [imagePath] = imageHash },
            null);
    }

    private static void WriteRelative(string root, string relativePath, byte[] bytes)
    {
        var path = ResolveRelative(root, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
    }

    private static string ResolveRelative(string root, string relativePath)
    {
        return Path.Combine(root, relativePath.Replace('\\', Path.DirectorySeparatorChar));
    }

    private static string Hash(byte[] bytes)
    {
        using (var sha256 = SHA256.Create())
        {
            return string.Concat(sha256.ComputeHash(bytes).Select(value => value.ToString("x2")));
        }
    }

    private static DeviceRecord CreateDevice(ProjectId projectId, DeviceId deviceId, string displayName)
    {
        return new DeviceRecord(
            deviceId,
            projectId,
            displayName,
            "192.0.2.10",
            22,
            "audit-user",
            TargetCategory.Server,
            ConnectionProtocol.Ssh,
            CredentialReference.New(),
            DateTimeOffset.UtcNow);
    }

    private static DatabaseConfirmationRecord CreateDatabaseConfirmation(
        ProjectId projectId,
        DeviceId deviceId,
        string product,
        string version)
    {
        return new DatabaseConfirmationRecord(
            projectId,
            deviceId,
            product,
            version,
            DatabaseInstallationType.LocalService,
            "postgresql.service",
            "5432/tcp",
            "只读进程和服务元数据",
            0.94,
            new DateTimeOffset(2026, 7, 17, 7, 30, 0, TimeSpan.Zero),
            "测评人员人工确认");
    }

    private static HostSoftwareDiscoveryBatchRecord CreateHostSoftwareBatch(
        ProjectId projectId,
        DeviceId deviceId,
        long revision,
        Guid? previousBatchId,
        DateTimeOffset recordedAt,
        params (HostSoftwareCategory Category, string Product, string Version, string InstanceName)[] definitions)
    {
        var batchId = Guid.NewGuid();
        var taskId = CollectionTaskId.New();
        var candidates = definitions
            .Select((definition, ordinal) => CreateHostSoftwareCandidate(
                batchId,
                taskId,
                ordinal,
                definition.Category,
                definition.Product,
                definition.Version,
                definition.InstanceName))
            .ToArray();
        return new HostSoftwareDiscoveryBatchRecord(
            batchId,
            projectId,
            deviceId,
            taskId,
            revision,
            previousBatchId,
            "read-only-host-discovery",
            candidates,
            recordedAt);
    }

    private static HostSoftwareDiscoveryCandidateRecord CreateHostSoftwareCandidate(
        Guid batchId,
        CollectionTaskId taskId,
        int ordinal,
        HostSoftwareCategory category,
        string product,
        string version,
        string instanceName)
    {
        var candidateId = Guid.NewGuid();
        var evidence = new HostSoftwareDiscoveryEvidenceRecord(
            Guid.NewGuid(),
            candidateId,
            0,
            taskId,
            ordinal,
            HostSoftwareEvidenceKind.Service,
            "host-discovery-services",
            instanceName + " active running",
            RawHash);
        return new HostSoftwareDiscoveryCandidateRecord(
            candidateId,
            batchId,
            ordinal,
            category,
            product,
            version,
            HostSoftwareInstallationType.LocalService,
            instanceName,
            null,
            0.91,
            new[] { evidence });
    }

    private static HostSoftwareCandidateDecisionRecord CreateHostSoftwareDecision(
        HostSoftwareDiscoveryCandidateRecord candidate,
        HostSoftwareCandidateDecision decision,
        string decidedBy,
        string decisionSource,
        string? reason,
        DateTimeOffset decidedAt)
    {
        return new HostSoftwareCandidateDecisionRecord(
            Guid.NewGuid(),
            candidate.CandidateId,
            decision,
            decidedBy,
            decisionSource,
            reason,
            decidedAt);
    }

    private static ExecutionRecord CreateFailedExecution(
        ProjectId projectId,
        DeviceId deviceId,
        string commandId,
        DateTimeOffset startedAt)
    {
        return new ExecutionRecord(
            projectId.ToString(),
            deviceId.ToString(),
            ConnectionProtocol.Ssh,
            "1.0.0",
            commandId,
            "hostname",
            startedAt,
            startedAt.AddSeconds(1),
            ExecutionStatus.Failed,
            1,
            null,
            null,
            Array.Empty<string>(),
            new Dictionary<string, string>(),
            "远程命令失败");
    }

    private static IEnumerable<EvidenceFileRecord> CreateEvidenceFiles(
        ProjectId projectId,
        DeviceId deviceId,
        ExecutionRecord execution)
    {
        yield return new EvidenceFileRecord(
            projectId,
            deviceId,
            execution.RawOutputPath!,
            execution.RawOutputSha256!,
            EvidenceFileKind.RawOutput,
            0,
            execution.CompletedAt!.Value);
        yield return new EvidenceFileRecord(
            projectId,
            deviceId,
            execution.EvidenceImagePaths[0],
            execution.EvidenceImageSha256s[execution.EvidenceImagePaths[0]],
            EvidenceFileKind.EvidenceImage,
            1,
            execution.CompletedAt.Value);
    }

    private sealed class FakeProjectRepository :
        IProjectRepository,
        IDatabaseConfirmationRepository,
        IHostSoftwareDiscoveryRepository
    {
        public IReadOnlyList<ExecutionRecord> Executions { get; set; } = Array.Empty<ExecutionRecord>();
        public IReadOnlyList<EvidenceFileRecord> EvidenceFiles { get; set; } = Array.Empty<EvidenceFileRecord>();
        public IReadOnlyList<DeviceRecord> Devices { get; set; } = Array.Empty<DeviceRecord>();
        public IReadOnlyList<ProjectRecord> Projects { get; set; } = Array.Empty<ProjectRecord>();
        public IReadOnlyList<DatabaseConfirmationRecord> DatabaseConfirmations { get; set; } =
            Array.Empty<DatabaseConfirmationRecord>();
        public IReadOnlyList<HostSoftwareDiscoveryBatchRecord> HostSoftwareHistories { get; set; } =
            Array.Empty<HostSoftwareDiscoveryBatchRecord>();
        public IReadOnlyDictionary<Guid, IReadOnlyList<HostSoftwareCandidateDecisionRecord>>
            HostSoftwareDecisions { get; set; } =
                new Dictionary<Guid, IReadOnlyList<HostSoftwareCandidateDecisionRecord>>();
        public Exception? ExecutionError { get; set; }
        public Exception? DatabaseConfirmationError { get; set; }
        public int ExecutionQueryCount { get; private set; }
        public int EvidenceQueryCount { get; private set; }
        public int DeviceQueryCount { get; private set; }
        public int DatabaseConfirmationQueryCount { get; private set; }
        public int HostSoftwareHistoryQueryCount { get; private set; }
        public int HostSoftwareDecisionQueryCount { get; private set; }
        public ProjectId RequestedProjectId { get; private set; }

        public Task<IReadOnlyList<ExecutionRecord>> GetExecutionsAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            ExecutionQueryCount++;
            RequestedProjectId = projectId;
            cancellationToken.ThrowIfCancellationRequested();
            if (ExecutionError != null)
            {
                throw ExecutionError;
            }

            return Task.FromResult(Executions);
        }

        public Task<IReadOnlyList<EvidenceFileRecord>> GetEvidenceFilesAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            EvidenceQueryCount++;
            RequestedProjectId = projectId;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(EvidenceFiles);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<ProjectId> CreateProjectAsync(string customerName, string projectName, string evidenceRoot, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DeviceId> AddDeviceAsync(ProjectId projectId, string displayName, string host, int port, CredentialReference credentialReference, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DeviceId> AddDeviceAsync(ProjectId projectId, string displayName, string host, int port, string userName, TargetCategory category, ConnectionProtocol protocol, CredentialReference credentialReference, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DeviceId> AddDeviceAsync(ProjectId projectId, string displayName, string host, int port, string userName, TargetCategory category, ConnectionProtocol protocol, SshAuthenticationMethod authenticationMethod, CredentialReference credentialReference, PrivateKeyReference? privateKeyReference, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task SaveExecutionAsync(ExecutionRecord record, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Projects);
        }
        public Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(ProjectId projectId, CancellationToken cancellationToken = default)
        {
            DeviceQueryCount++;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Devices);
        }
        public Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task SaveDatabaseConfirmationAsync(
            DatabaseConfirmationRecord record,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<DatabaseConfirmationRecord>> GetDatabaseConfirmationsAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            DatabaseConfirmationQueryCount++;
            cancellationToken.ThrowIfCancellationRequested();
            if (DatabaseConfirmationError != null)
            {
                throw DatabaseConfirmationError;
            }

            return Task.FromResult(DatabaseConfirmations);
        }

        public Task<HostSoftwareDiscoveryBatchRecord> AppendHostSoftwareDiscoveryBatchAsync(
            ProjectId projectId,
            DeviceId deviceId,
            CollectionTaskId collectionTaskId,
            IReadOnlyList<HostSoftwareDiscoveryCandidateInput> candidates,
            string discoverySource,
            DateTimeOffset recordedAt,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<HostSoftwareDiscoveryBatchRecord?> GetLatestHostSoftwareDiscoveryBatchAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<IReadOnlyList<HostSoftwareDiscoveryBatchRecord>> GetHostSoftwareDiscoveryHistoryAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            HostSoftwareHistoryQueryCount++;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<HostSoftwareDiscoveryBatchRecord>>(
                HostSoftwareHistories.Where(batch => batch.DeviceId.Equals(deviceId)).ToArray());
        }

        public Task<HostSoftwareCandidateDecisionRecord> AppendHostSoftwareCandidateDecisionAsync(
            Guid candidateId,
            HostSoftwareCandidateDecision decision,
            string decidedBy,
            string decisionSource,
            string? reason,
            DateTimeOffset decidedAt,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<IReadOnlyList<HostSoftwareCandidateDecisionRecord>> GetHostSoftwareCandidateDecisionsAsync(
            Guid batchId,
            CancellationToken cancellationToken = default)
        {
            HostSoftwareDecisionQueryCount++;
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyList<HostSoftwareCandidateDecisionRecord> decisions;
            return Task.FromResult(HostSoftwareDecisions.TryGetValue(batchId, out decisions)
                ? decisions
                : Array.Empty<HostSoftwareCandidateDecisionRecord>());
        }
    }
}
