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
    Failed
}

public sealed class CommandLibraryViewModel : INotifyPropertyChanged
{
    private readonly ICommandDraftService service;
    private readonly ICommandDraftFilePicker filePicker;
    private readonly DelegateCommand importCommand;
    private readonly DelegateCommand refreshCommand;
    private IReadOnlyList<CommandDraftListItemViewModel> drafts =
        Array.Empty<CommandDraftListItemViewModel>();
    private CommandLibraryState state;
    private string statusMessage = "正在读取本地命令草稿…";

    public CommandLibraryViewModel(
        ICommandDraftService service,
        ICommandDraftFilePicker filePicker)
    {
        this.service = service ?? throw new ArgumentNullException(nameof(service));
        this.filePicker = filePicker ?? throw new ArgumentNullException(nameof(filePicker));
        importCommand = new DelegateCommand(() => _ = PickAndImportAsync(), () => !IsBusy);
        refreshCommand = new DelegateCommand(() => _ = RefreshAsync(), () => !IsBusy);
        state = CommandLibraryState.Loading;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand ImportCommand => importCommand;
    public ICommand RefreshCommand => refreshCommand;
    public IReadOnlyList<CommandDraftListItemViewModel> Drafts => drafts;
    public CommandLibraryState State => state;
    public string StatusMessage => statusMessage;
    public bool IsBusy => State == CommandLibraryState.Loading || State == CommandLibraryState.Importing;
    public bool HasDrafts => Drafts.Count != 0;

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
                "导入完成：内容已强制保存为待校验草稿，当前版本不能发布或执行。");
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
