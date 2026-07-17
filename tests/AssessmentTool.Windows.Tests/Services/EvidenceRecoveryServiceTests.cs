using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Evidence;
using AssessmentTool.Windows.Storage;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class EvidenceRecoveryServiceTests : IDisposable
{
    private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "EvaluationTool.EvidenceRecovery",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Valid_pending_batch_is_verified_indexed_and_marker_is_removed()
    {
        var fixture = CreateFixture("valid");
        var repository = new RecordingRepository(fixture.Device);
        var service = new EvidenceRecoveryService(repository);

        var result = await service.RecoverAsync(fixture.Project);

        Assert.Equal(1, result.ScannedCount);
        Assert.Equal(1, result.RecoveredCount);
        Assert.Equal(0, result.FailedCount);
        Assert.False(File.Exists(fixture.MarkerPath));
        var saved = Assert.Single(repository.SavedExecutions);
        Assert.Equal(fixture.Project.Id.ToString(), saved.ProjectId);
        Assert.Equal(fixture.Device.Id.ToString(), saved.DeviceId);
        Assert.EndsWith(@"原始输出.txt", saved.RawOutputPath, StringComparison.Ordinal);
        Assert.DoesNotContain(root, saved.RawOutputPath!, StringComparison.OrdinalIgnoreCase);
        Assert.Single(saved.EvidenceImagePaths);
    }

    [Fact]
    public async Task Already_indexed_batch_is_idempotent_and_only_removes_marker()
    {
        var fixture = CreateFixture("existing");
        var existing = fixture.ToPersistedRecord();
        var repository = new RecordingRepository(fixture.Device, existing);
        var service = new EvidenceRecoveryService(repository);

        var result = await service.RecoverAsync(fixture.Project);

        Assert.Equal(1, result.AlreadyIndexedCount);
        Assert.Equal(0, result.RecoveredCount);
        Assert.Empty(repository.SavedExecutions);
        Assert.False(File.Exists(fixture.MarkerPath));
    }

    [Fact]
    public async Task Tampered_evidence_is_not_indexed_and_marker_is_retained()
    {
        var fixture = CreateFixture("tampered");
        File.AppendAllText(fixture.RawOutputPath, "tampered", Utf8);
        var repository = new RecordingRepository(fixture.Device);
        var service = new EvidenceRecoveryService(repository);

        var result = await service.RecoverAsync(fixture.Project);

        Assert.Equal(1, result.FailedCount);
        Assert.Empty(repository.SavedExecutions);
        Assert.True(File.Exists(fixture.MarkerPath));
        Assert.DoesNotContain("tampered", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Invalid_batch_does_not_prevent_another_valid_batch_from_recovery()
    {
        var invalid = CreateFixture("invalid");
        File.WriteAllText(Path.Combine(invalid.BatchDirectory, "执行记录.json"), "{}", Utf8);
        var valid = CreateFixture("valid-second", invalid.Project, invalid.Device);
        var repository = new RecordingRepository(valid.Device);
        var service = new EvidenceRecoveryService(repository);

        var result = await service.RecoverAsync(valid.Project);

        Assert.Equal(2, result.ScannedCount);
        Assert.Equal(1, result.RecoveredCount);
        Assert.Equal(1, result.FailedCount);
        Assert.Single(repository.SavedExecutions);
        Assert.True(File.Exists(invalid.MarkerPath));
        Assert.False(File.Exists(valid.MarkerPath));
    }

    [Fact]
    public async Task Manifest_for_unknown_device_cannot_be_imported_into_project()
    {
        var fixture = CreateFixture("foreign-device");
        var repository = new RecordingRepository(
            new DeviceRecord(
                DeviceId.New(),
                fixture.Project.Id,
                "其他设备",
                "192.0.2.99",
                22,
                CredentialReference.New(),
                DateTimeOffset.UtcNow));
        var service = new EvidenceRecoveryService(repository);

        var result = await service.RecoverAsync(fixture.Project);

        Assert.Equal(1, result.FailedCount);
        Assert.Empty(repository.SavedExecutions);
        Assert.True(File.Exists(fixture.MarkerPath));
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, true);
        }
    }

    private RecoveryFixture CreateFixture(
        string name,
        ProjectRecord? existingProject = null,
        DeviceRecord? existingDevice = null)
    {
        Directory.CreateDirectory(root);
        var project = existingProject ?? new ProjectRecord(
            ProjectId.New(), "测试客户", "测试项目", root, DateTimeOffset.UtcNow.AddDays(-1));
        var device = existingDevice ?? new DeviceRecord(
            DeviceId.New(), project.Id, "Linux服务器", "192.0.2.80", 22,
            CredentialReference.New(), DateTimeOffset.UtcNow.AddDays(-1));
        var batchDirectory = Path.Combine(root, "测试项目", "Linux服务器", "1.1.1", name);
        Directory.CreateDirectory(batchDirectory);
        var startedAt = new DateTimeOffset(2026, 7, 18, 1, 2, 3, TimeSpan.Zero).AddMinutes(name.Length);
        var rawOutput = "audit-output-" + name + Environment.NewLine;
        var imageName = "证据_001.png";
        var imagePath = Path.Combine(batchDirectory, imageName);
        var imageBytes = Encoding.ASCII.GetBytes("png-fixture-" + name);
        File.WriteAllBytes(imagePath, imageBytes);
        var localRecord = new ExecutionRecord(
            project.Id.ToString(),
            device.Id.ToString(),
            ConnectionProtocol.Ssh,
            "generic-linux-1.0.0",
            "generic-linux-hostname",
            "hostname",
            startedAt,
            startedAt.AddSeconds(1),
            ExecutionStatus.Succeeded,
            0,
            "原始输出.txt",
            Hash(Utf8.GetBytes(rawOutput)),
            new[] { imageName },
            new Dictionary<string, string> { [imageName] = Hash(imageBytes) },
            null);
        EvidenceManifest.FromExecutionRecord(localRecord, null).WriteToDirectory(batchDirectory, rawOutput);
        var markerPath = Path.Combine(batchDirectory, "待入库.txt");
        File.WriteAllText(markerPath, "pending", Utf8);
        return new RecoveryFixture(project, device, batchDirectory, markerPath, localRecord);
    }

    private static string Hash(byte[] bytes)
    {
        using (var sha256 = SHA256.Create())
        {
            return string.Concat(sha256.ComputeHash(bytes)
                .Select(value => value.ToString("x2", CultureInfo.InvariantCulture)));
        }
    }

    private sealed class RecoveryFixture
    {
        public RecoveryFixture(
            ProjectRecord project,
            DeviceRecord device,
            string batchDirectory,
            string markerPath,
            ExecutionRecord localRecord)
        {
            Project = project;
            Device = device;
            BatchDirectory = batchDirectory;
            MarkerPath = markerPath;
            LocalRecord = localRecord;
        }

        public ProjectRecord Project { get; }
        public DeviceRecord Device { get; }
        public string BatchDirectory { get; }
        public string MarkerPath { get; }
        public string RawOutputPath => Path.Combine(BatchDirectory, "原始输出.txt");
        public ExecutionRecord LocalRecord { get; }

        public ExecutionRecord ToPersistedRecord()
        {
            var batchRelative = BatchDirectory.Substring(Project.EvidenceRoot.Length)
                .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Replace(Path.DirectorySeparatorChar, '\\')
                .Replace(Path.AltDirectorySeparatorChar, '\\');
            var rawPath = batchRelative + "\\" + LocalRecord.RawOutputPath;
            var imagePaths = LocalRecord.EvidenceImagePaths
                .Select(path => batchRelative + "\\" + path)
                .ToArray();
            return new ExecutionRecord(
                LocalRecord.ProjectId,
                LocalRecord.DeviceId,
                LocalRecord.ConnectionProtocol,
                LocalRecord.CommandPackVersion,
                LocalRecord.CommandId,
                LocalRecord.CommandText,
                LocalRecord.StartedAt,
                LocalRecord.CompletedAt,
                LocalRecord.Status,
                LocalRecord.ExitCode,
                rawPath,
                LocalRecord.RawOutputSha256,
                imagePaths,
                imagePaths.ToDictionary(
                    path => path,
                    path => LocalRecord.EvidenceImageSha256s[
                        path.Substring(path.LastIndexOf('\\') + 1)],
                    StringComparer.OrdinalIgnoreCase),
                LocalRecord.ErrorText);
        }
    }

    private sealed class RecordingRepository : IProjectRepository
    {
        private readonly IReadOnlyList<DeviceRecord> devices;
        private readonly IReadOnlyList<ExecutionRecord> executions;

        public RecordingRepository(DeviceRecord device, params ExecutionRecord[] executions)
        {
            devices = new[] { device };
            this.executions = executions;
        }

        public List<ExecutionRecord> SavedExecutions { get; } = new List<ExecutionRecord>();

        public Task SaveExecutionAsync(ExecutionRecord record, CancellationToken cancellationToken = default)
        {
            SavedExecutions.Add(record);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default) => Task.FromResult(devices);

        public Task<IReadOnlyList<ExecutionRecord>> GetExecutionsAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default) => Task.FromResult(executions);

        public Task InitializeAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<ProjectId> CreateProjectAsync(string customerName, string projectName, string evidenceRoot, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DeviceId> AddDeviceAsync(ProjectId projectId, string displayName, string host, int port, CredentialReference credentialReference, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DeviceId> AddDeviceAsync(ProjectId projectId, string displayName, string host, int port, string userName, TargetCategory category, ConnectionProtocol protocol, CredentialReference credentialReference, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DeviceId> AddDeviceAsync(ProjectId projectId, string displayName, string host, int port, string userName, TargetCategory category, ConnectionProtocol protocol, SshAuthenticationMethod authenticationMethod, CredentialReference credentialReference, PrivateKeyReference? privateKeyReference, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<EvidenceFileRecord>> GetEvidenceFilesAsync(ProjectId projectId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
