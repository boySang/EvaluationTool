using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class ProjectEvidenceManifestExporterTests
{
    [Theory]
    [InlineData("password=SuperSecret123")]
    [InlineData("Authorization: Bearer abc.def.ghi")]
    [InlineData("Server=db01;User Id=audit;Password=secret")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----")]
    public void Sensitive_export_text_is_blocked_before_serialization(string value)
    {
        Assert.Throws<InvalidDataException>(() =>
            SensitiveExportTextPolicy.EnsureNoLikelySecrets(new[] { value }));
    }

    [Theory]
    [InlineData("show password policy")]
    [InlineData("grep '^PASS_MAX_DAYS' /etc/login.defs")]
    [InlineData("只读查询令牌有效期策略")]
    public void Read_only_policy_text_without_secret_values_is_allowed(string value)
    {
        SensitiveExportTextPolicy.EnsureNoLikelySecrets(new[] { value });
    }

    [Fact]
    public async Task Export_writes_verified_audit_manifest_without_credentials_or_absolute_evidence_root()
    {
        var project = new ProjectRecord(
            ProjectId.New(),
            "客户甲",
            "项目甲",
            @"C:\客户资料\项目甲",
            DateTimeOffset.Parse("2026-07-17T08:00:00Z"));
        var device = new DeviceRecord(
            DeviceId.New(),
            project.Id,
            "Linux服务器甲",
            "192.0.2.10",
            22,
            "audit-user",
            TargetCategory.Server,
            ConnectionProtocol.Ssh,
            SshAuthenticationMethod.Password,
            CredentialReference.New(),
            null,
            DateTimeOffset.Parse("2026-07-17T08:01:00Z"));
        var rawPath = @"Linux服务器甲\身份鉴别\批次\原始输出.txt";
        var imagePath = @"Linux服务器甲\身份鉴别\批次\证据_001.png";
        var hash = new string('a', 64);
        var execution = new ExecutionRecord(
            project.Id.ToString(),
            device.Id.ToString(),
            ConnectionProtocol.Ssh,
            "generic-linux@1.0.0",
            "linux.identity.passwd-policy",
            "getent login.defs",
            DateTimeOffset.Parse("2026-07-17T09:00:00Z"),
            DateTimeOffset.Parse("2026-07-17T09:00:02Z"),
            ExecutionStatus.Succeeded,
            0,
            rawPath,
            hash,
            new[] { imagePath },
            new Dictionary<string, string> { [imagePath] = hash },
            null);
        var evidenceFiles = new[]
        {
            new EvidenceFileRecord(project.Id, device.Id, rawPath, hash,
                EvidenceFileKind.RawOutput, 0, execution.StartedAt),
            new EvidenceFileRecord(project.Id, device.Id, imagePath, hash,
                EvidenceFileKind.EvidenceImage, 1, execution.StartedAt)
        };
        var repository = new FakeRepository(project, device, execution, evidenceFiles);
        var verifiedItem = new EvidenceCenterItem(
            device.Id.ToString(),
            device.DisplayName,
            execution.CommandId,
            execution.CommandText,
            execution.StartedAt,
            execution.CompletedAt,
            execution.Status,
            rawPath,
            new[] { imagePath },
            1,
            EvidenceShaStatus.Verified);
        var evidenceService = new FakeEvidenceCenterService(
            new EvidenceCenterSnapshot(project.Id, new[] { verifiedItem }));
        var generatedAt = DateTimeOffset.Parse("2026-07-17T10:00:00Z");
        var exporter = new ProjectEvidenceManifestExporter(
            repository,
            repository,
            repository,
            evidenceService,
            () => generatedAt);

        var directory = Path.Combine(Path.GetTempPath(), "EvaluationTool-export-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "项目甲-证据清单.json");
            var result = await exporter.ExportAsync(project, path);

            Assert.Equal(1, result.ExecutionCount);
            Assert.Equal(2, result.EvidenceFileCount);
            var json = File.ReadAllText(path);
            var document = JObject.Parse(json);
            Assert.Equal(1, (int?)document["schemaVersion"]);
            Assert.Equal("Verified", (string?)document["executions"]?[0]?["integrityStatus"]);
            Assert.Equal(hash, (string?)document["executions"]?[0]?["rawOutputSha256"]);
            Assert.Equal(imagePath, (string?)document["executions"]?[0]?["evidenceImages"]?[0]?["relativePath"]);
            Assert.Equal(1, (int?)document["summary"]?["verifiedExecutionCount"]);
            Assert.DoesNotContain(project.EvidenceRoot, json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(device.Host, json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(device.UserName, json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(device.CredentialReference.ToString(), json, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("不包含密码", json, StringComparison.Ordinal);
            Assert.Equal(project.Id, Assert.Single(evidenceService.VerifiedProjects));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Export_refuses_to_overwrite_existing_manifest()
    {
        var project = new ProjectRecord(
            ProjectId.New(), "客户", "项目", @"C:\Evidence", DateTimeOffset.UtcNow);
        var repository = new FakeRepository(project);
        var exporter = new ProjectEvidenceManifestExporter(
            repository,
            repository,
            repository,
            new FakeEvidenceCenterService(new EvidenceCenterSnapshot(
                project.Id,
                Array.Empty<EvidenceCenterItem>())),
            () => DateTimeOffset.UtcNow);
        var path = Path.Combine(Path.GetTempPath(), "EvaluationTool-existing-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, "do-not-overwrite");
        try
        {
            await Assert.ThrowsAsync<IOException>(() => exporter.ExportAsync(project, path));
            Assert.Equal("do-not-overwrite", File.ReadAllText(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private sealed class FakeEvidenceCenterService : IEvidenceCenterService
    {
        private readonly EvidenceCenterSnapshot snapshot;

        internal FakeEvidenceCenterService(EvidenceCenterSnapshot snapshot)
        {
            this.snapshot = snapshot;
        }

        internal List<ProjectId> VerifiedProjects { get; } = new List<ProjectId>();

        public Task<EvidenceCenterSnapshot> LoadAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default) => Task.FromResult(snapshot);

        public Task<EvidenceCenterSnapshot> VerifyAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            VerifiedProjects.Add(projectId);
            return Task.FromResult(snapshot);
        }
    }

    private sealed class FakeRepository :
        IProjectRepository,
        IDatabaseConfirmationRepository,
        IHostSoftwareDiscoveryRepository
    {
        private readonly ProjectRecord project;
        private readonly IReadOnlyList<DeviceRecord> devices;
        private readonly IReadOnlyList<ExecutionRecord> executions;
        private readonly IReadOnlyList<EvidenceFileRecord> evidenceFiles;

        internal FakeRepository(
            ProjectRecord project,
            DeviceRecord? device = null,
            ExecutionRecord? execution = null,
            IReadOnlyList<EvidenceFileRecord>? evidenceFiles = null)
        {
            this.project = project;
            devices = device == null ? Array.Empty<DeviceRecord>() : new[] { device };
            executions = execution == null ? Array.Empty<ExecutionRecord>() : new[] { execution };
            this.evidenceFiles = evidenceFiles ?? Array.Empty<EvidenceFileRecord>();
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<ProjectId> CreateProjectAsync(string customerName, string projectName, string evidenceRoot,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DeviceId> AddDeviceAsync(ProjectId projectId, string displayName, string host, int port,
            CredentialReference credentialReference, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DeviceId> AddDeviceAsync(ProjectId projectId, string displayName, string host, int port,
            string userName, TargetCategory category, ConnectionProtocol protocol,
            CredentialReference credentialReference, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DeviceId> AddDeviceAsync(ProjectId projectId, string displayName, string host, int port,
            string userName, TargetCategory category, ConnectionProtocol protocol,
            SshAuthenticationMethod authenticationMethod, CredentialReference credentialReference,
            PrivateKeyReference? privateKeyReference, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task SaveExecutionAsync(ExecutionRecord record, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ProjectRecord>>(new[] { project });
        public Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(ProjectId projectId,
            CancellationToken cancellationToken = default) => Task.FromResult(devices);
        public Task<IReadOnlyList<ExecutionRecord>> GetExecutionsAsync(ProjectId projectId,
            CancellationToken cancellationToken = default) => Task.FromResult(executions);
        public Task<IReadOnlyList<EvidenceFileRecord>> GetEvidenceFilesAsync(ProjectId projectId,
            CancellationToken cancellationToken = default) => Task.FromResult(evidenceFiles);
        public Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default) => Task.FromResult(11);
        public Task SaveDatabaseConfirmationAsync(DatabaseConfirmationRecord record,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<DatabaseConfirmationRecord>> GetDatabaseConfirmationsAsync(ProjectId projectId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<DatabaseConfirmationRecord>>(Array.Empty<DatabaseConfirmationRecord>());
        public Task<HostSoftwareDiscoveryBatchRecord> AppendHostSoftwareDiscoveryBatchAsync(
            ProjectId projectId, DeviceId deviceId, CollectionTaskId collectionTaskId,
            IReadOnlyList<HostSoftwareDiscoveryCandidateInput> candidates, string discoverySource,
            DateTimeOffset recordedAt, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<HostSoftwareDiscoveryBatchRecord?> GetLatestHostSoftwareDiscoveryBatchAsync(DeviceId deviceId,
            CancellationToken cancellationToken = default) => Task.FromResult<HostSoftwareDiscoveryBatchRecord?>(null);
        public Task<IReadOnlyList<HostSoftwareDiscoveryBatchRecord>> GetHostSoftwareDiscoveryHistoryAsync(
            DeviceId deviceId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<HostSoftwareDiscoveryBatchRecord>>(Array.Empty<HostSoftwareDiscoveryBatchRecord>());
        public Task<HostSoftwareCandidateDecisionRecord> AppendHostSoftwareCandidateDecisionAsync(Guid candidateId,
            HostSoftwareCandidateDecision decision, string decidedBy, string decisionSource, string? reason,
            DateTimeOffset decidedAt, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<HostSoftwareCandidateDecisionRecord>> GetHostSoftwareCandidateDecisionsAsync(
            Guid batchId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<HostSoftwareCandidateDecisionRecord>>(Array.Empty<HostSoftwareCandidateDecisionRecord>());
    }
}
