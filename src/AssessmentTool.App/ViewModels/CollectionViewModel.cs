using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Execution;

namespace AssessmentTool.App.ViewModels;

public enum CollectionViewModelState
{
    Idle,
    Ready,
    Running,
    Stopping,
    AwaitingConfirmation,
    AwaitingDatabaseConfirmation,
    ConfirmingDatabase,
    DatabaseConfirmed,
    Completed,
    Stopped,
    Failed
}

public sealed class CollectionViewModel : INotifyPropertyChanged
{
    private readonly ICollectionWorkflowService workflowService;
    private readonly IDatabaseConfirmationService databaseConfirmationService;
    private readonly DelegateCommand startCommand;
    private readonly DelegateCommand stopCommand;
    private readonly ParameterizedDelegateCommand<DetectionCandidate> confirmDetectionCommand;
    private readonly ParameterizedDelegateCommand<DatabaseInstanceCandidate> confirmDatabaseCommand;
    private ProjectRecord? selectedProject;
    private CollectionDeviceSelection? selectedDevice;
    private bool? requiredComponentAvailabilityOverride;
    private CancellationTokenSource? activeCancellation;
    private CollectionViewModelState state;
    private IReadOnlyList<DetectionCandidate> detectionCandidates = Array.Empty<DetectionCandidate>();
    private IReadOnlyList<DatabaseInstanceCandidate> databaseCandidates = Array.Empty<DatabaseInstanceCandidate>();
    private IReadOnlyList<CompletedCollectionCommand> completedCommands = Array.Empty<CompletedCollectionCommand>();
    private DatabaseInstanceCandidate? selectedDatabaseCandidate;
    private CollectionState? progressState;
    private string progressMessage = string.Empty;
    private string? currentCommand;
    private int completedCommandCount;
    private int totalCommandCount;
    private int activeGeneration;
    private CollectionError? error;

    public CollectionViewModel(
        ICollectionWorkflowService workflowService,
        IDatabaseConfirmationService databaseConfirmationService)
    {
        this.workflowService = workflowService ?? throw new ArgumentNullException(nameof(workflowService));
        this.databaseConfirmationService = databaseConfirmationService
            ?? throw new ArgumentNullException(nameof(databaseConfirmationService));
        state = CollectionViewModelState.Idle;
        startCommand = new DelegateCommand(() => _ = StartAsync(), CanStart);
        stopCommand = new DelegateCommand(Stop, () => State == CollectionViewModelState.Running);
        confirmDetectionCommand = new ParameterizedDelegateCommand<DetectionCandidate>(
            candidate => _ = ConfirmAndRetryAsync(candidate),
            candidate => State == CollectionViewModelState.AwaitingConfirmation
                && DetectionCandidates.Contains(candidate));
        confirmDatabaseCommand = new ParameterizedDelegateCommand<DatabaseInstanceCandidate>(
            candidate => _ = ConfirmDatabaseAsync(candidate),
            candidate => State == CollectionViewModelState.AwaitingDatabaseConfirmation
                && DatabaseCandidates.Contains(candidate));
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand StartCommand => startCommand;
    public ICommand StopCommand => stopCommand;
    public ICommand ConfirmDetectionCommand => confirmDetectionCommand;
    public ICommand ConfirmDatabaseCommand => confirmDatabaseCommand;
    public CollectionViewModelState State => state;
    public IReadOnlyList<DetectionCandidate> DetectionCandidates => detectionCandidates;
    public IReadOnlyList<DatabaseInstanceCandidate> DatabaseCandidates => databaseCandidates;
    public IReadOnlyList<CompletedCollectionCommand> CompletedCommands => completedCommands;
    public DatabaseInstanceCandidate? SelectedDatabaseCandidate => selectedDatabaseCandidate;
    public CollectionState? ProgressState => progressState;
    public string ProgressMessage => progressMessage;
    public string? CurrentCommand => currentCommand;
    public int CompletedCommandCount => completedCommandCount;
    public int TotalCommandCount => totalCommandCount;
    public CollectionError? Error => error;
    public bool IsDetectionConfirmationVisible => State == CollectionViewModelState.AwaitingConfirmation;
    public bool IsDatabaseConfirmationVisible => State == CollectionViewModelState.AwaitingDatabaseConfirmation;
    public bool IsComponentCenterNavigationSuggested =>
        selectedDevice != null && !IsRequiredComponentAvailable;

    public void SelectProject(ProjectRecord project)
    {
        EnsureSelectionCanChange();
        var nextProject = project ?? throw new ArgumentNullException(nameof(project));
        if (selectedProject == null || !selectedProject.Id.Equals(nextProject.Id))
        {
            selectedDevice = null;
            OnPropertyChanged(nameof(IsComponentCenterNavigationSuggested));
        }

        selectedProject = nextProject;
        RefreshReadiness();
    }

    public void SelectDevice(CollectionDeviceSelection deviceSelection)
    {
        EnsureSelectionCanChange();
        selectedDevice = deviceSelection ?? throw new ArgumentNullException(nameof(deviceSelection));
        OnPropertyChanged(nameof(IsComponentCenterNavigationSuggested));
        RefreshReadiness();
    }

    public void ClearDeviceSelection()
    {
        EnsureSelectionCanChange();
        selectedDevice = null;
        OnPropertyChanged(nameof(IsComponentCenterNavigationSuggested));
        RefreshReadiness();
    }

    public void SetRequiredComponentAvailability(bool isAvailable)
    {
        requiredComponentAvailabilityOverride = isAvailable;
        OnPropertyChanged(nameof(IsComponentCenterNavigationSuggested));
        RefreshReadiness();
    }

    public Task StartAsync()
    {
        if (!CanStart())
        {
            throw new InvalidOperationException("项目、设备、连接组件和主机指纹均就绪后才能开始采集。");
        }

        return RunAsync(null);
    }

    public Task ConfirmAndRetryAsync(DetectionCandidate candidate)
    {
        if (candidate == null)
        {
            throw new ArgumentNullException(nameof(candidate));
        }

        if (State != CollectionViewModelState.AwaitingConfirmation
            || !DetectionCandidates.Contains(candidate))
        {
            throw new InvalidOperationException("只能确认当前识别候选项。");
        }

        return RunAsync(candidate);
    }

    public void Stop()
    {
        if (activeCancellation != null && State == CollectionViewModelState.Running)
        {
            SetState(CollectionViewModelState.Stopping);
            activeCancellation.Cancel();
        }
    }

    public async Task ConfirmDatabaseAsync(DatabaseInstanceCandidate candidate)
    {
        if (candidate == null)
        {
            throw new ArgumentNullException(nameof(candidate));
        }

        if (State != CollectionViewModelState.AwaitingDatabaseConfirmation
            || !DatabaseCandidates.Contains(candidate))
        {
            throw new InvalidOperationException("只能确认当前数据库候选项。");
        }

        if (selectedProject == null || selectedDevice == null)
        {
            throw new InvalidOperationException("数据库确认缺少当前项目或设备。");
        }

        SetError(null);
        SetState(CollectionViewModelState.ConfirmingDatabase);
        try
        {
            await databaseConfirmationService.ConfirmAsync(
                selectedProject,
                selectedDevice.Device,
                candidate,
                CancellationToken.None);
            selectedDatabaseCandidate = candidate;
            OnPropertyChanged(nameof(SelectedDatabaseCandidate));
            SetState(CollectionViewModelState.DatabaseConfirmed);
        }
        catch (Exception exception)
        {
            SetError(new CollectionError(
                "数据库确认记录保存失败",
                "本地项目数据库无法保存本次人工确认记录",
                "检查本地数据目录权限和磁盘空间后重试",
                exception.GetType().Name));
            SetState(CollectionViewModelState.AwaitingDatabaseConfirmation);
        }
    }

    private bool CanStart()
    {
        return State != CollectionViewModelState.Running
            && State != CollectionViewModelState.Stopping
            && State != CollectionViewModelState.AwaitingConfirmation
            && State != CollectionViewModelState.AwaitingDatabaseConfirmation
            && State != CollectionViewModelState.ConfirmingDatabase
            && selectedProject != null
            && selectedDevice != null
            && selectedDevice.Device.ProjectId.Equals(selectedProject.Id)
            && IsRequiredComponentAvailable
            && selectedDevice.IsHostKeyTrusted;
    }

    private bool IsRequiredComponentAvailable =>
        requiredComponentAvailabilityOverride
        ?? selectedDevice?.IsRequiredComponentAvailable
        ?? false;

    private async Task RunAsync(DetectionCandidate? confirmedCandidate)
    {
        if (selectedProject == null || selectedDevice == null)
        {
            throw new InvalidOperationException("尚未选择项目和设备。");
        }

        using (var cancellation = new CancellationTokenSource())
        {
            var generation = unchecked(++activeGeneration);
            activeCancellation = cancellation;
            SetError(null);
            SetDetectionCandidates(Array.Empty<DetectionCandidate>());
            SetDatabaseCandidates(Array.Empty<DatabaseInstanceCandidate>());
            selectedDatabaseCandidate = null;
            OnPropertyChanged(nameof(SelectedDatabaseCandidate));
            SetState(CollectionViewModelState.Running);

            try
            {
                var request = new CollectionWorkflowRequest(
                    selectedProject,
                    selectedDevice,
                    confirmedCandidate);
                var progress = new ContextProgress<CollectionProgress>(value =>
                {
                    if (generation == activeGeneration
                        && (State == CollectionViewModelState.Running
                            || State == CollectionViewModelState.Stopping))
                    {
                        ApplyProgress(value);
                    }
                });
                var result = await workflowService.RunAsync(request, progress, cancellation.Token);
                if (cancellation.IsCancellationRequested)
                {
                    SetCompletedCommands(Array.Empty<CompletedCollectionCommand>());
                    SetDetectionCandidates(Array.Empty<DetectionCandidate>());
                    SetDatabaseCandidates(Array.Empty<DatabaseInstanceCandidate>());
                    SetState(CollectionViewModelState.Stopped);
                }
                else
                {
                    Apply(result);
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
                SetState(CollectionViewModelState.Stopped);
            }
            catch (Exception exception)
            {
                if (cancellation.IsCancellationRequested)
                {
                    SetError(null);
                    SetState(CollectionViewModelState.Stopped);
                }
                else
                {
                    SetError(new CollectionError(
                        "采集任务失败",
                        "连接、组件或采集服务发生异常",
                        "检查组件中心和设备连接后重试",
                        exception.GetType().Name));
                    SetState(CollectionViewModelState.Failed);
                }
            }
            finally
            {
                if (ReferenceEquals(activeCancellation, cancellation))
                {
                    activeCancellation = null;
                }

                RaiseCommandStates();
            }
        }
    }

    private void Apply(CollectionWorkflowResult result)
    {
        if (result == null)
        {
            throw new InvalidOperationException("采集服务没有返回结果。");
        }

        SetCompletedCommands(result.CompletedCommands);
        switch (result.Outcome)
        {
            case CollectionWorkflowOutcome.Completed:
                SetDetectionCandidates(Array.Empty<DetectionCandidate>());
                SetState(CollectionViewModelState.Completed);
                break;
            case CollectionWorkflowOutcome.RequiresConfirmation:
                SetDetectionCandidates(result.DetectionCandidates);
                SetState(CollectionViewModelState.AwaitingConfirmation);
                break;
            case CollectionWorkflowOutcome.RequiresDatabaseConfirmation:
                SetDetectionCandidates(Array.Empty<DetectionCandidate>());
                SetDatabaseCandidates(result.DatabaseCandidates);
                SetState(CollectionViewModelState.AwaitingDatabaseConfirmation);
                break;
            case CollectionWorkflowOutcome.Stopped:
                SetDetectionCandidates(Array.Empty<DetectionCandidate>());
                SetState(CollectionViewModelState.Stopped);
                break;
            case CollectionWorkflowOutcome.Failed:
                SetDetectionCandidates(Array.Empty<DetectionCandidate>());
                SetError((result.Error ?? throw new InvalidOperationException("失败结果缺少结构化错误。")).Redacted());
                SetState(CollectionViewModelState.Failed);
                break;
            default:
                throw new InvalidOperationException("采集服务返回了未知状态。");
        }
    }

    private void RefreshReadiness()
    {
        if (State != CollectionViewModelState.Running && State != CollectionViewModelState.Stopping)
        {
            SetState(CanStart() ? CollectionViewModelState.Ready : CollectionViewModelState.Idle);
        }

        RaiseCommandStates();
    }

    private void EnsureSelectionCanChange()
    {
        if (State == CollectionViewModelState.Running || State == CollectionViewModelState.Stopping)
        {
            throw new InvalidOperationException("采集任务运行或停止过程中不能更换项目和设备。");
        }
    }

    private void SetState(CollectionViewModelState value)
    {
        if (state == value)
        {
            return;
        }

        state = value;
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(IsDetectionConfirmationVisible));
        OnPropertyChanged(nameof(IsDatabaseConfirmationVisible));
        RaiseCommandStates();
    }

    private void SetDetectionCandidates(IEnumerable<DetectionCandidate> candidates)
    {
        detectionCandidates = new ReadOnlyCollection<DetectionCandidate>(candidates.ToArray());
        OnPropertyChanged(nameof(DetectionCandidates));
    }

    private void SetCompletedCommands(IEnumerable<CompletedCollectionCommand> commands)
    {
        completedCommands = new ReadOnlyCollection<CompletedCollectionCommand>(commands.ToArray());
        OnPropertyChanged(nameof(CompletedCommands));
    }

    private void SetDatabaseCandidates(IEnumerable<DatabaseInstanceCandidate> candidates)
    {
        databaseCandidates = new ReadOnlyCollection<DatabaseInstanceCandidate>(candidates.ToArray());
        OnPropertyChanged(nameof(DatabaseCandidates));
    }

    private void ApplyProgress(CollectionProgress progress)
    {
        if (progress == null)
        {
            return;
        }

        progressState = progress.State;
        progressMessage = progress.Message;
        currentCommand = progress.CommandId;
        completedCommandCount = progress.CompletedCommands;
        totalCommandCount = progress.TotalCommands;
        OnPropertyChanged(nameof(ProgressState));
        OnPropertyChanged(nameof(ProgressMessage));
        OnPropertyChanged(nameof(CurrentCommand));
        OnPropertyChanged(nameof(CompletedCommandCount));
        OnPropertyChanged(nameof(TotalCommandCount));
    }

    private void SetError(CollectionError? value)
    {
        error = value;
        OnPropertyChanged(nameof(Error));
    }

    private void RaiseCommandStates()
    {
        startCommand.RaiseCanExecuteChanged();
        stopCommand.RaiseCanExecuteChanged();
        confirmDetectionCommand.RaiseCanExecuteChanged();
        confirmDatabaseCommand.RaiseCanExecuteChanged();
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    private sealed class ContextProgress<T> : IProgress<T>
    {
        private readonly SynchronizationContext? context = SynchronizationContext.Current;
        private readonly Action<T> report;

        public ContextProgress(Action<T> report)
        {
            this.report = report ?? throw new ArgumentNullException(nameof(report));
        }

        public void Report(T value)
        {
            if (context == null || ReferenceEquals(context, SynchronizationContext.Current))
            {
                report(value);
                return;
            }

            context.Post(state => report((T)state!), value);
        }
    }
}
