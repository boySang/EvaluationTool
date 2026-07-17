using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Commands;
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
        Assert.Contains("不能发布或执行", viewModel.StatusMessage);
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
}
