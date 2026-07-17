using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows.Input;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.ViewModels;

public enum CollectionTaskHistoryViewModelState
{
    NoProject,
    Loading,
    Ready,
    Empty,
    Failed
}

public sealed class CollectionTaskHistoryItem
{
    public CollectionTaskHistoryItem(
        CollectionTaskRecord task,
        CollectionTaskEventRecord? latestEvent)
    {
        Task = task ?? throw new ArgumentNullException(nameof(task));
        LatestEvent = latestEvent;
        State = latestEvent?.State ?? CollectionTaskState.Ready;
        StatusText = GetStatusText(State);
        StatusDescription = GetStatusDescription(State);
    }

    public CollectionTaskRecord Task { get; }
    public CollectionTaskEventRecord? LatestEvent { get; }
    public CollectionTaskId TaskId => Task.Id;
    public DeviceId DeviceId => Task.DeviceId;
    public string Host => Task.Host;
    public int Port => Task.Port;
    public DateTimeOffset CreatedAt => Task.CreatedAt;
    public DateTimeOffset LastUpdatedAt => LatestEvent?.OccurredAt ?? Task.CreatedAt;
    public int CommandCount => Task.Commands.Count;
    public CollectionTaskState State { get; }
    public string StatusText { get; }
    public string StatusDescription { get; }
    public bool IsInterrupted => State == CollectionTaskState.Interrupted;

    private static string GetStatusText(CollectionTaskState state)
    {
        switch (state)
        {
            case CollectionTaskState.Ready:
                return "等待开始";
            case CollectionTaskState.Running:
                return "正在采集";
            case CollectionTaskState.Stopping:
                return "正在安全停止";
            case CollectionTaskState.Completed:
                return "采集完成";
            case CollectionTaskState.Failed:
                return "采集失败";
            case CollectionTaskState.Stopped:
                return "已停止";
            case CollectionTaskState.Interrupted:
                return "上次采集异常中断";
            default:
                return "状态未知";
        }
    }

    private static string GetStatusDescription(CollectionTaskState state)
    {
        switch (state)
        {
            case CollectionTaskState.Ready:
                return "任务已保存，尚未开始执行。";
            case CollectionTaskState.Running:
                return "软件正在执行只读采集命令。";
            case CollectionTaskState.Stopping:
                return "正在结束当前操作并保存已完成的证据。";
            case CollectionTaskState.Completed:
                return "任务已完成，可前往证据页面查看结果。";
            case CollectionTaskState.Failed:
                return "任务未完成，请查看任务日志后重新创建采集任务。";
            case CollectionTaskState.Stopped:
                return "任务已由用户停止，不会自动继续。";
            case CollectionTaskState.Interrupted:
                return "软件上次运行期间意外退出。为保护客户设备，本任务不会自动恢复，请检查后重新创建采集任务。";
            default:
                return "暂时无法识别任务状态，请刷新后重试。";
        }
    }
}

public sealed class CollectionTaskHistoryViewModel : INotifyPropertyChanged
{
    private readonly object loadSync = new object();
    private readonly ICollectionTaskRepository repository;
    private readonly DelegateCommand refreshCommand;
    private IReadOnlyList<CollectionTaskHistoryItem> items = Array.Empty<CollectionTaskHistoryItem>();
    private ProjectRecord? selectedProject;
    private CollectionTaskHistoryViewModelState state = CollectionTaskHistoryViewModelState.NoProject;
    private Task? activeLoad;
    private int activeLoadGeneration;
    private int selectionGeneration;
    private string statusMessage = "请选择项目以查看采集任务历史。";
    private string whatHappened = string.Empty;
    private string possibleCause = string.Empty;
    private string howToFix = string.Empty;
    private string technicalDetails = string.Empty;

    public CollectionTaskHistoryViewModel(ICollectionTaskRepository repository)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
        refreshCommand = new DelegateCommand(() => _ = RefreshAsync(), () => CanRefresh);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ProjectRecord? SelectedProject => selectedProject;
    public IReadOnlyList<CollectionTaskHistoryItem> Items => items;
    public CollectionTaskHistoryViewModelState State => state;
    public ICommand RefreshCommand => refreshCommand;
    public bool HasItems => Items.Count != 0;
    public bool CanRefresh => selectedProject != null && State != CollectionTaskHistoryViewModelState.Loading;
    public string StatusMessage => statusMessage;
    public string WhatHappened => whatHappened;
    public string PossibleCause => possibleCause;
    public string HowToFix => howToFix;
    public string TechnicalDetails => technicalDetails;

    public Task SelectProjectAsync(ProjectRecord? project)
    {
        var generation = unchecked(++selectionGeneration);
        selectedProject = project;
        OnPropertyChanged(nameof(SelectedProject));
        SetItems(Array.Empty<CollectionTaskHistoryItem>());
        ClearError();

        if (project == null)
        {
            SetStatusMessage("请选择项目以查看采集任务历史。");
            SetState(CollectionTaskHistoryViewModelState.NoProject);
            return Task.CompletedTask;
        }

        return BeginLoad(project, generation);
    }

    public Task RefreshAsync()
    {
        var project = selectedProject;
        return project == null
            ? Task.CompletedTask
            : BeginLoad(project, selectionGeneration);
    }

    private Task BeginLoad(ProjectRecord project, int generation)
    {
        lock (loadSync)
        {
            if (activeLoad != null && !activeLoad.IsCompleted && activeLoadGeneration == generation)
            {
                return activeLoad;
            }

            activeLoadGeneration = generation;
            activeLoad = LoadCoreAsync(project, generation);
            return activeLoad;
        }
    }

    private async Task LoadCoreAsync(ProjectRecord project, int generation)
    {
        ClearError();
        SetStatusMessage("正在读取采集任务历史…");
        SetState(CollectionTaskHistoryViewModelState.Loading);
        try
        {
            var tasks = await repository.GetCollectionTasksAsync(project.Id);
            var eventLoads = tasks.Select(async task => new CollectionTaskHistoryItem(
                task,
                (await repository.GetCollectionTaskEventsAsync(task.Id))
                    .OrderByDescending(item => item.Revision)
                    .FirstOrDefault()));
            var loadedItems = await Task.WhenAll(eventLoads);
            if (!IsCurrent(project, generation))
            {
                return;
            }

            SetItems(loadedItems
                .OrderByDescending(item => item.LastUpdatedAt)
                .ThenByDescending(item => item.CreatedAt));
            if (Items.Count == 0)
            {
                SetStatusMessage("当前项目还没有采集任务。创建并运行任务后，历史记录会显示在这里。");
                SetState(CollectionTaskHistoryViewModelState.Empty);
            }
            else
            {
                SetStatusMessage("已加载 " + Items.Count + " 条采集任务记录。");
                SetState(CollectionTaskHistoryViewModelState.Ready);
            }
        }
        catch (Exception exception)
        {
            if (IsCurrent(project, generation))
            {
                SetFailure(exception);
            }
        }
    }

    private bool IsCurrent(ProjectRecord project, int generation)
    {
        return generation == selectionGeneration
            && selectedProject != null
            && selectedProject.Id.Equals(project.Id);
    }

    private void SetFailure(Exception exception)
    {
        SetItems(Array.Empty<CollectionTaskHistoryItem>());
        whatHappened = "采集任务历史加载失败";
        possibleCause = "本地项目数据库暂时不可用，或任务记录读取不完整。";
        howToFix = "请单击“刷新”重试；如仍失败，请检查本机数据目录权限和磁盘状态。";
        technicalDetails = exception.GetType().Name;
        OnPropertyChanged(nameof(WhatHappened));
        OnPropertyChanged(nameof(PossibleCause));
        OnPropertyChanged(nameof(HowToFix));
        OnPropertyChanged(nameof(TechnicalDetails));
        SetStatusMessage("暂时无法显示采集任务历史。");
        SetState(CollectionTaskHistoryViewModelState.Failed);
    }

    private void ClearError()
    {
        whatHappened = string.Empty;
        possibleCause = string.Empty;
        howToFix = string.Empty;
        technicalDetails = string.Empty;
        OnPropertyChanged(nameof(WhatHappened));
        OnPropertyChanged(nameof(PossibleCause));
        OnPropertyChanged(nameof(HowToFix));
        OnPropertyChanged(nameof(TechnicalDetails));
    }

    private void SetItems(IEnumerable<CollectionTaskHistoryItem> value)
    {
        items = new ReadOnlyCollection<CollectionTaskHistoryItem>(value.ToArray());
        OnPropertyChanged(nameof(Items));
        OnPropertyChanged(nameof(HasItems));
    }

    private void SetState(CollectionTaskHistoryViewModelState value)
    {
        if (state == value)
        {
            return;
        }

        state = value;
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(CanRefresh));
        refreshCommand.RaiseCanExecuteChanged();
    }

    private void SetStatusMessage(string value)
    {
        statusMessage = value;
        OnPropertyChanged(nameof(StatusMessage));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
