using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class CollectionEvidenceServiceTests : IDisposable
{
    private static readonly DateTimeOffset StartedAt =
        new DateTimeOffset(2026, 7, 17, 8, 30, 0, TimeSpan.FromHours(8));
    private readonly string temporaryRoot = Path.Combine(
        Path.GetTempPath(),
        "assessment-tool-evidence-service-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Successful_output_saves_exact_raw_output_paginated_png_hashes_manifest_and_index()
    {
        var repository = new RecordingRepository();
        var service = new CollectionEvidenceService(repository);
        var fixture = CreateFixture();
        var rawOutput = string.Join("\r\n", Enumerable.Range(1, 400).Select(index =>
            index.ToString("0000") + " | Linux 只读采集输出 | password policy status"));

        var saved = await service.SaveAsync(
            fixture.Project,
            fixture.Device,
            "linux-pack-1.0.0",
            fixture.Command,
            Output(fixture.Command.Id, rawOutput),
            CancellationToken.None);

        Assert.True(saved.IsIndexed);
        Assert.True(saved.EvidenceImagePaths.Count > 1);
        Assert.All(saved.EvidenceImagePaths, path => Assert.True(File.Exists(path)));
        Assert.True(File.Exists(saved.ManifestPath));
        Assert.Equal(rawOutput, File.ReadAllText(Path.Combine(saved.BatchDirectory, "原始输出.txt"), Encoding.UTF8));
        Assert.Equal(Hash(rawOutput), saved.Execution.RawOutputSha256);
        Assert.Equal(ExecutionStatus.Succeeded, saved.Execution.Status);
        Assert.Equal(saved.EvidenceImagePaths.Count, saved.Execution.EvidenceImageSha256s.Count);
        Assert.All(saved.Execution.EvidenceImageSha256s, item =>
            Assert.Equal(HashFile(Path.Combine(fixture.Project.EvidenceRoot, item.Key)), item.Value));
        Assert.Same(repository.SavedExecution, saved.Execution);
    }

    [Fact]
    public async Task Remote_failure_still_saves_output_screenshot_and_traceable_failed_execution()
    {
        var repository = new RecordingRepository();
        var service = new CollectionEvidenceService(repository);
        var fixture = CreateFixture();
        var output = new CommandOutput(
            fixture.Command.Id,
            "partial device output",
            "connection closed by remote host",
            1,
            RemoteExecutionOutcome.Failed,
            RemoteFailureCategory.NetworkFailed,
            StartedAt,
            StartedAt.AddSeconds(4));

        var saved = await service.SaveAsync(
            fixture.Project,
            fixture.Device,
            "linux-pack-1.0.0",
            fixture.Command,
            output);

        Assert.Equal(ExecutionStatus.Failed, saved.Execution.Status);
        Assert.Equal(output.UserErrorMessage, saved.Execution.ErrorText);
        Assert.NotEmpty(saved.EvidenceImagePaths);
        Assert.Contains("partial device output", File.ReadAllText(
            Path.Combine(saved.BatchDirectory, "原始输出.txt"), Encoding.UTF8));
        Assert.Contains("connection closed by remote host", File.ReadAllText(
            Path.Combine(saved.BatchDirectory, "原始输出.txt"), Encoding.UTF8));
        Assert.Contains("\"errorCategory\": \"NetworkFailed\"", File.ReadAllText(saved.ManifestPath));
        Assert.NotNull(repository.SavedExecution);
    }

    [Fact]
    public async Task Empty_success_output_is_saved_as_traceable_evidence_failure()
    {
        var repository = new RecordingRepository();
        var service = new CollectionEvidenceService(repository);
        var fixture = CreateFixture();

        var error = await Assert.ThrowsAsync<CollectionEvidenceException>(() => service.SaveAsync(
            fixture.Project,
            fixture.Device,
            "linux-pack-1.0.0",
            fixture.Command,
            Output(fixture.Command.Id, string.Empty)));

        Assert.True(error.SavedEvidence.IsIndexed);
        Assert.Equal(ExecutionStatus.Failed, error.SavedEvidence.Execution.Status);
        Assert.Empty(error.SavedEvidence.EvidenceImagePaths);
        Assert.Equal(Hash(string.Empty), error.SavedEvidence.Execution.RawOutputSha256);
        Assert.True(File.Exists(error.SavedEvidence.ManifestPath));
        Assert.Equal(string.Empty, File.ReadAllText(
            Path.Combine(error.SavedEvidence.BatchDirectory, "原始输出.txt"), Encoding.UTF8));
        Assert.Contains("EvidenceRenderingFailed", File.ReadAllText(error.SavedEvidence.ManifestPath));
        Assert.NotNull(repository.SavedExecution);
    }

    [Fact]
    public async Task Repository_failure_keeps_files_and_writes_recovery_marker()
    {
        var repository = new RecordingRepository { SaveFailure = new IOException("database unavailable") };
        var service = new CollectionEvidenceService(repository);
        var fixture = CreateFixture();

        var error = await Assert.ThrowsAsync<CollectionEvidenceException>(() => service.SaveAsync(
            fixture.Project,
            fixture.Device,
            "linux-pack-1.0.0",
            fixture.Command,
            Output(fixture.Command.Id, "actual output")));

        Assert.False(error.SavedEvidence.IsIndexed);
        Assert.True(File.Exists(error.SavedEvidence.ManifestPath));
        Assert.True(File.Exists(Path.Combine(error.SavedEvidence.BatchDirectory, "原始输出.txt")));
        Assert.True(File.Exists(Path.Combine(error.SavedEvidence.BatchDirectory, "待入库.txt")));
        Assert.DoesNotContain("database unavailable", File.ReadAllText(
            Path.Combine(error.SavedEvidence.BatchDirectory, "待入库.txt")));
    }

    public void Dispose()
    {
        if (Directory.Exists(temporaryRoot))
        {
            Directory.Delete(temporaryRoot, true);
        }
    }

    private Fixture CreateFixture()
    {
        Directory.CreateDirectory(temporaryRoot);
        var projectId = ProjectId.New();
        var project = new ProjectRecord(projectId, "客户甲", "项目甲", temporaryRoot, StartedAt.AddDays(-1));
        var device = new DeviceRecord(
            DeviceId.New(),
            projectId,
            "Linux服务器甲",
            "192.0.2.10",
            22,
            "audit-user",
            TargetCategory.Server,
            ConnectionProtocol.Ssh,
            CredentialReference.New(),
            StartedAt.AddHours(-1));
        return new Fixture(project, device, CreateCommand());
    }

    private static CommandOutput Output(string commandId, string standardOutput)
    {
        return new CommandOutput(
            commandId,
            standardOutput,
            string.Empty,
            0,
            RemoteExecutionOutcome.Succeeded,
            null,
            StartedAt,
            StartedAt.AddSeconds(2));
    }

    private static CommandDefinition CreateCommand()
    {
        var constructor = Assert.Single(
            typeof(CommandDefinition).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic));
        return (CommandDefinition)constructor.Invoke(new object?[]
        {
            "linux-password-policy",
            "查询密码策略",
            TargetCategory.Server,
            "grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS' /etc/login.defs",
            VerificationStatus.Verified,
            true,
            null,
            "Linux",
            null,
            null,
            "身份鉴别",
            "*",
            "只读审计账户",
            CommandRiskLevel.Low,
            TimeSpan.FromSeconds(30),
            PagingBehavior.NotApplicable,
            "密码策略参数",
            new DateTime(2026, 7, 17),
            "https://man7.org/linux/man-pages/man5/login.defs.5.html",
            false
        });
    }

    private static string Hash(string value)
    {
        using (var sha256 = SHA256.Create())
        {
            return ToHex(sha256.ComputeHash(new UTF8Encoding(false, true).GetBytes(value)));
        }
    }

    private static string HashFile(string path)
    {
        using (var stream = File.OpenRead(path))
        using (var sha256 = SHA256.Create())
        {
            return ToHex(sha256.ComputeHash(stream));
        }
    }

    private static string ToHex(IEnumerable<byte> bytes)
    {
        return string.Concat(bytes.Select(value => value.ToString("x2")));
    }

    private sealed class Fixture
    {
        public Fixture(ProjectRecord project, DeviceRecord device, CommandDefinition command)
        {
            Project = project;
            Device = device;
            Command = command;
        }

        public ProjectRecord Project { get; }
        public DeviceRecord Device { get; }
        public CommandDefinition Command { get; }
    }

    private sealed class RecordingRepository : IProjectRepository
    {
        public ExecutionRecord? SavedExecution { get; private set; }
        public Exception? SaveFailure { get; set; }

        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<ProjectId> CreateProjectAsync(
            string customerName,
            string projectName,
            string evidenceRoot,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<DeviceId> AddDeviceAsync(
            ProjectId projectId,
            string displayName,
            string host,
            int port,
            CredentialReference credentialReference,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<DeviceId> AddDeviceAsync(
            ProjectId projectId,
            string displayName,
            string host,
            int port,
            string userName,
            TargetCategory category,
            ConnectionProtocol protocol,
            SshAuthenticationMethod authenticationMethod,
            CredentialReference credentialReference,
            PrivateKeyReference? privateKeyReference,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<DeviceId> AddDeviceAsync(
            ProjectId projectId,
            string displayName,
            string host,
            int port,
            string userName,
            TargetCategory category,
            ConnectionProtocol protocol,
            CredentialReference credentialReference,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task SaveExecutionAsync(ExecutionRecord record, CancellationToken cancellationToken = default)
        {
            if (SaveFailure != null)
            {
                return Task.FromException(SaveFailure);
            }

            SavedExecution = record;
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ProjectRecord>>(Array.Empty<ProjectRecord>());

        public Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<DeviceRecord>>(Array.Empty<DeviceRecord>());

        public Task<IReadOnlyList<ExecutionRecord>> GetExecutionsAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ExecutionRecord>>(Array.Empty<ExecutionRecord>());

        public Task<IReadOnlyList<EvidenceFileRecord>> GetEvidenceFilesAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<EvidenceFileRecord>>(Array.Empty<EvidenceFileRecord>());

        public Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default) => Task.FromResult(3);
    }
}
