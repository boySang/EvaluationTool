using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Xunit;

namespace AssessmentTool.Windows.Tests.ViewModels;

public sealed class CommandLibraryViewModelTests
{
    [Fact]
    public async Task Import_keeps_draft_pending_and_refreshes_visible_audit_data()
    {
        var record = CreateRecord();
        var service = new FakeCommandDraftService(record);
        var viewModel = new CommandLibraryViewModel(
            service,
            new FakeFilePicker(@"C:\imports\draft.json"));

        await viewModel.InitializeAsync();
        await viewModel.PickAndImportAsync();

        Assert.Equal(CommandLibraryState.Ready, viewModel.State);
        var item = Assert.Single(viewModel.Drafts);
        Assert.Equal("待校验 · 禁止执行", item.ReviewStatusText);
        Assert.Equal(1, item.BlockerCount);
        Assert.False(item.Record.IsExecutable);
        Assert.Equal(1, service.ImportCount);
        Assert.Contains("草稿不能直接执行", viewModel.StatusMessage);
    }

    [Fact]
    public async Task Cancelled_file_selection_does_not_import_or_change_state()
    {
        var service = new FakeCommandDraftService(CreateRecord());
        var viewModel = new CommandLibraryViewModel(service, new FakeFilePicker(null));
        await viewModel.InitializeAsync();

        await viewModel.PickAndImportAsync();

        Assert.Equal(CommandLibraryState.Empty, viewModel.State);
        Assert.Equal(0, service.ImportCount);
    }

    [Fact]
    public async Task Publish_and_project_lock_refresh_visible_immutable_version_state()
    {
        var draft = CreatePublishableRecord();
        var draftService = new FakeCommandDraftService(draft);
        var releaseService = new FakeCommandPackReleaseService(draft.Id);
        var viewModel = new CommandLibraryViewModel(
            draftService,
            new FakeFilePicker(@"C:\imports\safe.json"),
            releaseService)
        {
            ReviewerName = "reviewer-01"
        };
        await viewModel.InitializeAsync();
        await viewModel.PickAndImportAsync();
        var project = new ProjectRecord(
            ProjectId.New(),
            "客户",
            "项目 A",
            @"C:\Evidence",
            DateTimeOffset.UtcNow);
        await viewModel.SelectProjectAsync(project);

        await viewModel.ReviewAndPublishAsync(Assert.Single(viewModel.Drafts));
        var published = Assert.Single(viewModel.PublishedPacks);
        await viewModel.LockToProjectAsync(published);

        Assert.Equal(CommandLibraryState.Ready, viewModel.State);
        var locked = Assert.Single(viewModel.PublishedPacks);
        Assert.True(locked.IsCurrentProjectLock);
        Assert.Equal("当前项目已锁定", locked.ProjectLockActionText);
        Assert.Equal(1, releaseService.PublishCount);
        Assert.Equal(1, releaseService.LockCount);
    }

    private static CommandDraftArchiveRecord CreateRecord()
    {
        return new CommandDraftArchiveRecord(
            Guid.NewGuid(),
            "draft.json",
            new string('a', 64),
            "{}",
            new DateTimeOffset(2026, 7, 17, 8, 0, 0, TimeSpan.Zero),
            new[]
            {
                new CommandDraftItem(0, "unsafe", "危险样例", "rm -rf /tmp/test", "Server", "High")
            },
            new[]
            {
                new CommandDraftFinding(
                    CommandDraftFindingSeverity.Blocker,
                    "OBVIOUS_MUTATION",
                    "检测到明显修改语句。",
                    0)
            });
    }

    private static CommandDraftArchiveRecord CreatePublishableRecord()
    {
        return new CommandDraftArchiveRecord(
            Guid.NewGuid(),
            "safe.json",
            new string('b', 64),
            "{}",
            DateTimeOffset.UtcNow,
            new[] { new CommandDraftItem(0, "safe", "安全样例", "hostname", "Server", "Low") },
            Array.Empty<CommandDraftFinding>());
    }

    private sealed class FakeFilePicker : ICommandDraftFilePicker
    {
        private readonly string? path;

        public FakeFilePicker(string? path)
        {
            this.path = path;
        }

        public string? SelectJsonFile()
        {
            return path;
        }
    }

    private sealed class FakeCommandDraftService : ICommandDraftService
    {
        private readonly CommandDraftArchiveRecord importedRecord;
        private bool imported;

        public FakeCommandDraftService(CommandDraftArchiveRecord importedRecord)
        {
            this.importedRecord = importedRecord;
        }

        public int ImportCount { get; private set; }

        public Task<IReadOnlyList<CommandDraftArchiveRecord>> LoadAsync(
            CancellationToken cancellationToken = default)
        {
            IReadOnlyList<CommandDraftArchiveRecord> records = imported
                ? new[] { importedRecord }
                : Array.Empty<CommandDraftArchiveRecord>();
            return Task.FromResult(records);
        }

        public Task<CommandDraftArchiveRecord> ImportAsync(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            ImportCount++;
            imported = true;
            return Task.FromResult(importedRecord);
        }
    }

    private sealed class FakeCommandPackReleaseService : ICommandPackReleaseService
    {
        private readonly Guid draftId;
        private PublishedCommandPackRecord? published;
        private ProjectCommandPackLockRecord? currentLock;

        public FakeCommandPackReleaseService(Guid draftId)
        {
            this.draftId = draftId;
        }

        public int PublishCount { get; private set; }
        public int LockCount { get; private set; }

        public Task<CommandPackReleaseSnapshot> LoadAsync(
            ProjectId? projectId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new CommandPackReleaseSnapshot(
                published == null ? Array.Empty<PublishedCommandPackRecord>() : new[] { published },
                currentLock == null ? Array.Empty<ProjectCommandPackLockRecord>() : new[] { currentLock }));
        }

        public Task<PublishedCommandPackRecord> ReviewAndPublishAsync(
            Guid selectedDraftId,
            string reviewedBy,
            CancellationToken cancellationToken = default)
        {
            Assert.Equal(draftId, selectedDraftId);
            PublishCount++;
            published = new PublishedCommandPackRecord(
                "generic-linux",
                "Linux 安全命令",
                "1.0.0",
                "https://vendor.example/linux",
                new string('c', 64),
                "{}",
                draftId,
                new string('b', 64),
                reviewedBy,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow);
            return Task.FromResult(published);
        }

        public Task<ProjectCommandPackLockRecord> LockToProjectAsync(
            ProjectId projectId,
            string packId,
            string version,
            string source,
            CancellationToken cancellationToken = default)
        {
            LockCount++;
            currentLock = new ProjectCommandPackLockRecord(
                Guid.NewGuid(),
                projectId,
                packId,
                version,
                1,
                null,
                source,
                DateTimeOffset.UtcNow);
            return Task.FromResult(currentLock);
        }

        public Task<CommandPack?> LoadCurrentProjectPackAsync(
            ProjectId projectId,
            string packId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<CommandPack?>(null);
        }
    }
}
