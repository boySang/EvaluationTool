using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
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
            Devices = new[] { CreateDevice(projectId, deviceId, "Linux服务器甲") }
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
        Assert.Equal(1, item.ScreenshotCount);
        Assert.Equal("1 张", item.ScreenshotCountText);
        Assert.Equal("索引完整", item.ShaStatusText);
        Assert.Equal(1, repository.ExecutionQueryCount);
        Assert.Equal(1, repository.EvidenceQueryCount);
        Assert.Equal(1, repository.DeviceQueryCount);
        Assert.Equal(projectId, repository.RequestedProjectId);
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

    private sealed class FakeProjectRepository : IProjectRepository
    {
        public IReadOnlyList<ExecutionRecord> Executions { get; set; } = Array.Empty<ExecutionRecord>();
        public IReadOnlyList<EvidenceFileRecord> EvidenceFiles { get; set; } = Array.Empty<EvidenceFileRecord>();
        public IReadOnlyList<DeviceRecord> Devices { get; set; } = Array.Empty<DeviceRecord>();
        public Exception? ExecutionError { get; set; }
        public int ExecutionQueryCount { get; private set; }
        public int EvidenceQueryCount { get; private set; }
        public int DeviceQueryCount { get; private set; }
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
        public Task SaveExecutionAsync(ExecutionRecord record, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(ProjectId projectId, CancellationToken cancellationToken = default)
        {
            DeviceQueryCount++;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Devices);
        }
        public Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
