using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows.Input;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Commands;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.ViewModels;

public enum CommandLibraryState
{
    Loading,
    Empty,
    Ready,
    Importing,
    Publishing,
    Locking,
    Failed
}

public sealed class CommandLibraryViewModel : INotifyPropertyChanged
{
    private readonly ICommandDraftService service;
    private readonly ICommandPackReleaseService releaseService;
    private readonly ICommandDraftFilePicker filePicker;
    private readonly DelegateCommand importCommand;
    private readonly DelegateCommand refreshCommand;
    private readonly ParameterizedDelegateCommand<CommandDraftListItemViewModel> publishCommand;
    private readonly ParameterizedDelegateCommand<PublishedCommandPackListItemViewModel> lockCommand;
    private IReadOnlyList<CommandDraftListItemViewModel> drafts =
        Array.Empty<CommandDraftListItemViewModel>();
    private IReadOnlyList<PublishedCommandPackListItemViewModel> publishedPacks =
        Array.Empty<PublishedCommandPackListItemViewModel>();
    private ProjectRecord? selectedProject;
    private string reviewerName = Environment.UserName;
    private int releaseLoadGeneration;
    private CommandLibraryState state;
    private string statusMessage = "正在读取本地命令草稿…";

    public CommandLibraryViewModel(
        ICommandDraftService service,
        ICommandDraftFilePicker filePicker)
        : this(service, filePicker, new EmptyCommandPackReleaseService())
    {
    }

    public CommandLibraryViewModel(
        ICommandDraftService service,
        ICommandDraftFilePicker filePicker,
        ICommandPackReleaseService releaseService)
    {
        this.service = service ?? throw new ArgumentNullException(nameof(service));
        this.filePicker = filePicker ?? throw new ArgumentNullException(nameof(filePicker));
        this.releaseService = releaseService ?? throw new ArgumentNullException(nameof(releaseService));
        importCommand = new DelegateCommand(() => _ = PickAndImportAsync(), () => !IsBusy);
        refreshCommand = new DelegateCommand(() => _ = RefreshAsync(), () => !IsBusy);
        publishCommand = new ParameterizedDelegateCommand<CommandDraftListItemViewModel>(
            value => _ = ReviewAndPublishAsync(value),
            value => !IsBusy && value.BlockerCount == 0 && !string.IsNullOrWhiteSpace(ReviewerName));
        lockCommand = new ParameterizedDelegateCommand<PublishedCommandPackListItemViewModel>(
            value => _ = LockToProjectAsync(value),
            value => !IsBusy && selectedProject != null && !value.IsCurrentProjectLock);
        state = CommandLibraryState.Loading;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand ImportCommand => importCommand;
    public ICommand RefreshCommand => refreshCommand;
    public ICommand PublishCommand => publishCommand;
    public ICommand LockCommand => lockCommand;
    public IReadOnlyList<CommandDraftListItemViewModel> Drafts => drafts;
    public IReadOnlyList<PublishedCommandPackListItemViewModel> PublishedPacks => publishedPacks;
    public CommandLibraryState State => state;
    public string StatusMessage => statusMessage;
    public bool IsBusy => State == CommandLibraryState.Loading
        || State == CommandLibraryState.Importing
        || State == CommandLibraryState.Publishing
        || State == CommandLibraryState.Locking;
    public bool HasDrafts => Drafts.Count != 0;
    public bool HasPublishedPacks => PublishedPacks.Count != 0;
    public string SelectedProjectText => selectedProject == null
        ? "尚未选择项目，发布后暂不能锁定版本。"
        : "当前项目：" + selectedProject.ProjectName;
    public string ReviewerName
    {
        get => reviewerName;
        set
        {
            var normalized = value ?? string.Empty;
            if (string.Equals(reviewerName, normalized, StringComparison.Ordinal))
            {
                return;
            }

            reviewerName = normalized;
            OnPropertyChanged();
            publishCommand.RaiseCanExecuteChanged();
        }
    }

    internal static CommandLibraryViewModel CreateEmpty()
    {
        return new CommandLibraryViewModel(
            new EmptyCommandDraftService(),
            new EmptyCommandDraftFilePicker());
    }

    public async Task InitializeAsync()
    {
        await RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        SetState(CommandLibraryState.Loading, "正在读取本地命令草稿…");
        try
        {
            SetDrafts(await service.LoadAsync());
            await RefreshPublishedAsync();
            SetState(HasDrafts ? CommandLibraryState.Ready : CommandLibraryState.Empty,
                HasDrafts
                    ? "所有导入内容均为待校验草稿，不能执行。"
                    : "尚未导入命令草稿。可导入不超过 1 MB 的 JSON 文件。");
        }
        catch (Exception exception)
        {
            SetState(CommandLibraryState.Failed,
                "命令草稿暂时无法读取。请检查本地数据目录权限后重试（"
                + exception.GetType().Name + "）。");
        }
    }

    public async Task SelectProjectAsync(ProjectRecord? project)
    {
        selectedProject = project;
        OnPropertyChanged(nameof(SelectedProjectText));
        lockCommand.RaiseCanExecuteChanged();
        if (!IsBusy)
        {
            await RefreshPublishedAsync();
        }
    }

    public async Task PickAndImportAsync()
    {
        var selectedPath = filePicker.SelectJsonFile();
        if (selectedPath == null)
        {
            return;
        }

        var path = selectedPath.Trim();
        if (path.Length == 0)
        {
            return;
        }

        SetState(CommandLibraryState.Importing, "正在进行离线结构检查，不会连接客户设备…");
        try
        {
            await service.ImportAsync(path);
            SetDrafts(await service.LoadAsync());
            SetState(CommandLibraryState.Ready,
                "导入完成：草稿不能直接执行；修正全部阻断项后可由审核人员进行安全发布。");
        }
        catch (CommandDraftImportException exception)
        {
            SetState(CommandLibraryState.Failed, exception.Message);
        }
        catch (Exception exception)
        {
            SetState(CommandLibraryState.Failed,
                "导入失败，未连接客户设备，也未执行任何命令（"
                + exception.GetType().Name + "）。");
        }
    }

    public async Task ReviewAndPublishAsync(CommandDraftListItemViewModel item)
    {
        SetState(CommandLibraryState.Publishing, "正在逐条复核只读策略并生成不可变命令包版本…");
        try
        {
            await releaseService.ReviewAndPublishAsync(item.Record.Id, ReviewerName);
            await RefreshPublishedAsync();
            SetState(CommandLibraryState.Ready,
                "发布完成：命令包已固定 SHA-256，但只有锁定到项目后才会进入该项目的执行选择。");
        }
        catch (CommandPackReleaseException exception)
        {
            SetState(CommandLibraryState.Failed, exception.Message);
        }
        catch (Exception exception)
        {
            SetState(CommandLibraryState.Failed,
                "命令包发布失败，未连接客户设备（" + exception.GetType().Name + "）。");
        }
    }

    public async Task LockToProjectAsync(PublishedCommandPackListItemViewModel item)
    {
        var project = selectedProject;
        if (project == null)
        {
            return;
        }

        SetState(CommandLibraryState.Locking, "正在追加项目命令包锁定记录，不会修改历史版本…");
        try
        {
            await releaseService.LockToProjectAsync(
                project.Id,
                item.Record.PackId,
                item.Record.Version,
                "测评人员在命令库界面锁定或回滚版本");
            await RefreshPublishedAsync();
            SetState(CommandLibraryState.Ready,
                "项目命令包版本已锁定；后续切换或回滚也会保留完整历史。 ");
        }
        catch (Exception exception)
        {
            SetState(CommandLibraryState.Failed,
                "项目命令包版本锁定失败，原锁定保持不变（" + exception.GetType().Name + "）。");
        }
    }

    private async Task RefreshPublishedAsync()
    {
        var projectId = selectedProject?.Id;
        var generation = unchecked(++releaseLoadGeneration);
        var snapshot = await releaseService.LoadAsync(projectId);
        var currentProjectId = selectedProject?.Id;
        if (generation != releaseLoadGeneration
            || projectId.HasValue != currentProjectId.HasValue
            || (projectId.HasValue && !projectId.Value.Equals(currentProjectId.Value)))
        {
            return;
        }

        var locks = snapshot.CurrentLocks.ToDictionary(item => item.PackId, StringComparer.OrdinalIgnoreCase);
        publishedPacks = new ReadOnlyCollection<PublishedCommandPackListItemViewModel>(
            snapshot.PublishedPacks
                .Select(item => new PublishedCommandPackListItemViewModel(
                    item,
                    locks.TryGetValue(item.PackId, out var current) ? current : null))
                .ToArray());
        OnPropertyChanged(nameof(PublishedPacks));
        OnPropertyChanged(nameof(HasPublishedPacks));
        lockCommand.RaiseCanExecuteChanged();
    }

    private void SetDrafts(IEnumerable<CommandDraftArchiveRecord> values)
    {
        drafts = new ReadOnlyCollection<CommandDraftListItemViewModel>(
            values.Select(value => new CommandDraftListItemViewModel(value)).ToArray());
        OnPropertyChanged(nameof(Drafts));
        OnPropertyChanged(nameof(HasDrafts));
    }

    private void SetState(CommandLibraryState value, string message)
    {
        state = value;
        statusMessage = message;
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(StatusMessage));
        OnPropertyChanged(nameof(IsBusy));
        importCommand.RaiseCanExecuteChanged();
        refreshCommand.RaiseCanExecuteChanged();
        publishCommand.RaiseCanExecuteChanged();
        lockCommand.RaiseCanExecuteChanged();
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    private sealed class EmptyCommandDraftService : ICommandDraftService
    {
        public Task<IReadOnlyList<CommandDraftArchiveRecord>> LoadAsync(
            System.Threading.CancellationToken cancellationToken = default)
        {
            return Task.FromResult((IReadOnlyList<CommandDraftArchiveRecord>)
                Array.Empty<CommandDraftArchiveRecord>());
        }

        public Task<CommandDraftArchiveRecord> ImportAsync(
            string filePath,
            System.Threading.CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("当前未配置命令草稿存储。");
        }
    }

    private sealed class EmptyCommandDraftFilePicker : ICommandDraftFilePicker
    {
        public string? SelectJsonFile()
        {
            return null;
        }
    }

    private sealed class EmptyCommandPackReleaseService : ICommandPackReleaseService
    {
        public Task<CommandPackReleaseSnapshot> LoadAsync(
            ProjectId? projectId,
            System.Threading.CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new CommandPackReleaseSnapshot(
                Array.Empty<PublishedCommandPackRecord>(),
                Array.Empty<ProjectCommandPackLockRecord>()));
        }

        public Task<PublishedCommandPackRecord> ReviewAndPublishAsync(
            Guid draftId,
            string reviewedBy,
            System.Threading.CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("当前未配置命令包发布服务。");
        }

        public Task<ProjectCommandPackLockRecord> LockToProjectAsync(
            ProjectId projectId,
            string packId,
            string version,
            string source,
            System.Threading.CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("当前未配置项目命令包锁定服务。");
        }

        public Task<CommandPack?> LoadCurrentProjectPackAsync(
            ProjectId projectId,
            string packId,
            System.Threading.CancellationToken cancellationToken = default)
        {
            return Task.FromResult<CommandPack?>(null);
        }
    }
}

public sealed class CommandDraftListItemViewModel
{
    public CommandDraftListItemViewModel(CommandDraftArchiveRecord record)
    {
        Record = record ?? throw new ArgumentNullException(nameof(record));
        Findings = record.Findings;
    }

    public CommandDraftArchiveRecord Record { get; }
    public string SourceFileName => Record.SourceFileName;
    public string RawSha256 => Record.RawSha256;
    public string ImportedAtText => Record.ImportedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public int CommandCount => Record.Commands.Count;
    public IReadOnlyList<CommandDraftFinding> Findings { get; }
    public int BlockerCount => Findings.Count(finding => finding.Severity == CommandDraftFindingSeverity.Blocker);
    public string ReviewStatusText => "待校验 · 禁止执行";
}

public sealed class PublishedCommandPackListItemViewModel
{
    public PublishedCommandPackListItemViewModel(
        PublishedCommandPackRecord record,
        ProjectCommandPackLockRecord? currentLock)
    {
        Record = record ?? throw new ArgumentNullException(nameof(record));
        CurrentLock = currentLock;
    }

    public PublishedCommandPackRecord Record { get; }
    public ProjectCommandPackLockRecord? CurrentLock { get; }
    public string PackName => Record.PackName;
    public string PackId => Record.PackId;
    public string Version => Record.Version;
    public string RawSha256 => Record.RawSha256;
    public string OfficialSource => Record.OfficialSource;
    public string ReviewedBy => Record.ReviewedBy;
    public string PublishedAtText => Record.PublishedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public bool IsCurrentProjectLock => CurrentLock != null
        && string.Equals(CurrentLock.Version, Record.Version, StringComparison.Ordinal);
    public string ProjectLockActionText => CurrentLock == null
        ? "锁定到当前项目"
        : IsCurrentProjectLock
            ? "当前项目已锁定"
            : "切换/回滚到此版本";
    public string ProjectLockStatusText => CurrentLock == null
        ? "当前项目尚未锁定此命令包"
        : "当前项目锁定版本：" + CurrentLock.Version + "（修订 " + CurrentLock.Revision + "）";
}
