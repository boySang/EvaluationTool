using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class CommandPackReleaseServiceTests
{
    [Fact]
    public async Task Review_publish_lock_and_reload_preserve_the_verified_immutable_snapshot()
    {
        var draft = CreateDraft("show version");
        var repository = new FakeRepository(draft);
        var service = new CommandPackReleaseService(repository, repository);

        var published = await service.ReviewAndPublishAsync(draft.Id, "reviewer-01");
        var projectId = ProjectId.New();
        var locked = await service.LockToProjectAsync(
            projectId,
            published.PackId,
            published.Version,
            "单元测试人工锁定");
        var loaded = await service.LoadCurrentProjectPackAsync(
            projectId,
            published.PackId);

        Assert.Equal("reviewer-01", published.ReviewedBy);
        Assert.Equal(1, locked.Revision);
        Assert.NotNull(loaded);
        Assert.Equal(published.RawSha256, loaded!.Sha256);
        Assert.Equal("show-version", Assert.Single(loaded.Commands).Id);
        Assert.Single(repository.Published);
        Assert.Single(repository.Locks);
    }

    [Fact]
    public async Task Unsafe_draft_is_rejected_before_any_published_record_is_written()
    {
        var draft = CreateDraft("show version; reboot");
        var repository = new FakeRepository(draft);
        var service = new CommandPackReleaseService(repository, repository);

        var exception = await Assert.ThrowsAsync<CommandPackReleaseException>(
            () => service.ReviewAndPublishAsync(draft.Id, "reviewer-01"));

        Assert.Contains("未通过", exception.Message);
        Assert.Empty(repository.Published);
        Assert.Empty(repository.Locks);
    }

    private static CommandDraftArchiveRecord CreateDraft(string commandText)
    {
        var json = "{"
            + "\"id\":\"generic-linux\",\"name\":\"Linux 项目命令\",\"version\":\"1.0.0\","
            + "\"officialSource\":\"https://vendor.example/linux\",\"commands\":[{"
            + "\"id\":\"show-version\",\"title\":\"查看版本\",\"targetCategory\":\"NetworkDevice\","
            + "\"commandText\":\"" + commandText + "\",\"verificationStatus\":\"Verified\",\"isReadOnly\":true,"
            + "\"vendor\":\"ExampleVendor\",\"productFamily\":\"ExampleSwitch\","
            + "\"minimumVersion\":\"1.0\",\"maximumVersion\":\"9.9\",\"checkItem\":\"BASELINE\","
            + "\"modelRange\":\"*\",\"accountRequirement\":\"只读账户\",\"riskLevel\":\"Low\","
            + "\"timeoutSeconds\":30,\"pagingBehavior\":\"DisablePaging\",\"resultDescription\":\"版本信息\","
            + "\"verificationDate\":\"2025-01-01\",\"officialSource\":\"https://vendor.example/show-version\","
            + "\"optional\":false}]}";
        var imported = new CommandDraftImporter().Import(
            Encoding.UTF8.GetBytes(json),
            "generic-linux.json",
            DateTimeOffset.UtcNow);
        return new CommandDraftArchiveRecord(
            Guid.NewGuid(),
            imported.SourceFileName,
            imported.RawSha256,
            imported.RawJson,
            imported.ImportedAt,
            imported.Commands,
            imported.Findings);
    }

    private sealed class FakeRepository : ICommandDraftRepository, ICommandPackPublishingRepository
    {
        private readonly CommandDraftArchiveRecord draft;

        public FakeRepository(CommandDraftArchiveRecord draft)
        {
            this.draft = draft;
        }

        public List<PublishedCommandPackRecord> Published { get; } = new List<PublishedCommandPackRecord>();
        public List<ProjectCommandPackLockRecord> Locks { get; } = new List<ProjectCommandPackLockRecord>();

        public Task<Guid> SaveCommandDraftAsync(
            CommandDraftImportResult value,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<CommandDraftArchiveRecord>> GetCommandDraftsAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult((IReadOnlyList<CommandDraftArchiveRecord>)new[] { draft });
        }

        public Task<PublishedCommandPackRecord> PublishCommandPackAsync(
            PublishedCommandPackRecord record,
            CancellationToken cancellationToken = default)
        {
            Published.Add(record);
            return Task.FromResult(record);
        }

        public Task<PublishedCommandPackRecord?> GetPublishedCommandPackAsync(
            string packId,
            string version,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Published.SingleOrDefault(item =>
                item.PackId == packId && item.Version == version));
        }

        public Task<IReadOnlyList<PublishedCommandPackRecord>> GetPublishedCommandPacksAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult((IReadOnlyList<PublishedCommandPackRecord>)Published.ToArray());
        }

        public Task<ProjectCommandPackLockRecord> AppendProjectCommandPackLockAsync(
            ProjectId projectId,
            string packId,
            string version,
            long expectedRevision,
            string lockSource,
            DateTimeOffset lockedAt,
            CancellationToken cancellationToken = default)
        {
            var current = Locks.LastOrDefault(item => item.ProjectId.Equals(projectId) && item.PackId == packId);
            Assert.Equal(current?.Revision ?? 0, expectedRevision);
            var record = new ProjectCommandPackLockRecord(
                Guid.NewGuid(),
                projectId,
                packId,
                version,
                expectedRevision + 1,
                current?.Id,
                lockSource,
                lockedAt);
            Locks.Add(record);
            return Task.FromResult(record);
        }

        public Task<ProjectCommandPackLockRecord?> GetCurrentProjectCommandPackLockAsync(
            ProjectId projectId,
            string packId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Locks.LastOrDefault(item =>
                item.ProjectId.Equals(projectId) && item.PackId == packId));
        }

        public Task<IReadOnlyList<ProjectCommandPackLockRecord>> GetCurrentProjectCommandPackLocksAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            var values = Locks
                .Where(item => item.ProjectId.Equals(projectId))
                .GroupBy(item => item.PackId)
                .Select(group => group.OrderByDescending(item => item.Revision).First())
                .ToArray();
            return Task.FromResult((IReadOnlyList<ProjectCommandPackLockRecord>)values);
        }

        public Task<IReadOnlyList<ProjectCommandPackLockRecord>> GetProjectCommandPackLockHistoryAsync(
            ProjectId projectId,
            string packId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult((IReadOnlyList<ProjectCommandPackLockRecord>)Locks
                .Where(item => item.ProjectId.Equals(projectId) && item.PackId == packId)
                .ToArray());
        }
    }
}
