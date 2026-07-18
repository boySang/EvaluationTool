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
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.ViewModels;

public enum CollectionViewModelState
{
    Idle,
    Ready,
    RestoringIdentification,
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
    private static readonly CollectionAdapterOption GenericLinuxAdapter = new CollectionAdapterOption(
        CollectionAdapterId.GenericLinux,
        "通用 Linux 服务器",
        "仅适用于 SSH Linux 服务器；执行固定系统识别、基线查询和只读数据库/中间件发现命令。");
    private static readonly CollectionAdapterOption HuaweiVrpAdapter = new CollectionAdapterOption(
        CollectionAdapterId.HuaweiVrp,
        "华为 VRP 网络设备",
        "仅适用于已确认的华为 VRP 设备；当前执行版本识别和 AAA 配置概要只读查询，不适用于 H3C、Cisco、锐捷等厂商。");
    private static readonly CollectionAdapterOption H3cComwareAdapter = new CollectionAdapterOption(
        CollectionAdapterId.H3cComware,
        "H3C Comware 7/9 网络设备",
        "仅适用于已确认的 H3C Comware 7.1 或 9.x 设备；当前执行版本识别和全局口令控制策略只读查询，不适用于 Comware 5、华为、Cisco、锐捷等设备。");
    private static readonly CollectionAdapterOption WindowsServerSshAdapter = new CollectionAdapterOption(
        CollectionAdapterId.WindowsServerSsh,
        "Windows Server（SSH）",
        "仅适用于已开通 OpenSSH 且由管理员确认不是域控制器的 Windows Server 2016/2019/2022/2025 成员服务器；软件当前不能自动判定服务器角色，初版不支持域控制器。");
    private static readonly CollectionAdapterOption NginxLinuxSshAdapter = new CollectionAdapterOption(
        CollectionAdapterId.NginxLinuxSsh,
        "Nginx（Linux SSH）",
        "仅适用于可通过 /usr/sbin/nginx 访问的官方 Nginx Linux 安装；只查询 -v/-V 版本和构建参数，不测试、读取或重载配置，不适用于 OpenResty、自定义路径或容器内实例。");
    private readonly ICollectionWorkflowService workflowService;
    private readonly IDatabaseConfirmationService databaseConfirmationService;
    private readonly IHostSoftwareCandidateConfirmationService? hostSoftwareConfirmationService;
    private readonly IPendingDeviceIdentificationRepository? pendingIdentificationRepository;
    private readonly IPendingHostSoftwareDiscoveryRepository? pendingHostSoftwareRepository;
    private readonly DelegateCommand startCommand;
    private readonly DelegateCommand stopCommand;
    private readonly ParameterizedDelegateCommand<DetectionCandidate> confirmDetectionCommand;
    private readonly ParameterizedDelegateCommand<DatabaseInstanceCandidate> confirmDatabaseCommand;
    private readonly ParameterizedDelegateCommand<HostSoftwareDiscoveryCandidateRecord> confirmHostSoftwareCommand;
    private readonly ParameterizedDelegateCommand<HostSoftwareDiscoveryCandidateRecord> rejectHostSoftwareCommand;
    private ProjectRecord? selectedProject;
    private CollectionDeviceSelection? selectedDevice;
    private bool? requiredComponentAvailabilityOverride;
    private CancellationTokenSource? activeCancellation;
    private CollectionViewModelState state;
    private IReadOnlyList<DetectionCandidate> detectionCandidates = Array.Empty<DetectionCandidate>();
    private IReadOnlyList<DatabaseInstanceCandidate> databaseCandidates = Array.Empty<DatabaseInstanceCandidate>();
    private IReadOnlyList<HostSoftwareDiscoveryCandidateRecord> hostSoftwareCandidates =
        Array.Empty<HostSoftwareDiscoveryCandidateRecord>();
    private IReadOnlyList<CompletedCollectionCommand> completedCommands = Array.Empty<CompletedCollectionCommand>();
    private IReadOnlyList<CollectionAdapterOption> adapterOptions = Array.Empty<CollectionAdapterOption>();
    private CollectionAdapterOption? selectedAdapterOption;
    private DatabaseInstanceCandidate? selectedDatabaseCandidate;
    private CollectionState? progressState;
    private string progressMessage = string.Empty;
    private string? currentCommand;
    private int completedCommandCount;
    private int totalCommandCount;
    private int activeGeneration;
    private int pendingIdentificationLoadGeneration;
    private Guid? pendingIdentificationBatchId;
    private DeviceId pendingIdentificationDeviceId;
    private Guid? pendingHostSoftwareBatchId;
    private DeviceId pendingHostSoftwareDeviceId;
    private bool isRecoveredIdentification;
    private bool isRestoringIdentification;
    private CollectionError? error;

    public CollectionViewModel(
        ICollectionWorkflowService workflowService,
        IDatabaseConfirmationService databaseConfirmationService,
        IPendingDeviceIdentificationRepository? pendingIdentificationRepository = null,
        IHostSoftwareCandidateConfirmationService? hostSoftwareConfirmationService = null,
        IPendingHostSoftwareDiscoveryRepository? pendingHostSoftwareRepository = null)
    {
        this.workflowService = workflowService ?? throw new ArgumentNullException(nameof(workflowService));
        this.databaseConfirmationService = databaseConfirmationService
            ?? throw new ArgumentNullException(nameof(databaseConfirmationService));
        this.pendingIdentificationRepository = pendingIdentificationRepository;
        this.hostSoftwareConfirmationService = hostSoftwareConfirmationService;
        this.pendingHostSoftwareRepository = pendingHostSoftwareRepository;
        state = CollectionViewModelState.Idle;
        startCommand = new DelegateCommand(() => _ = StartAsync(), CanStart);
        stopCommand = new DelegateCommand(Stop, () => State == CollectionViewModelState.Running);
        confirmDetectionCommand = new ParameterizedDelegateCommand<DetectionCandidate>(
            candidate => _ = ConfirmAndRetryAsync(candidate),
            CanConfirmDetection);
        confirmDatabaseCommand = new ParameterizedDelegateCommand<DatabaseInstanceCandidate>(
            candidate => _ = ConfirmDatabaseAsync(candidate),
            candidate => State == CollectionViewModelState.AwaitingDatabaseConfirmation
                && DatabaseCandidates.Contains(candidate));
        confirmHostSoftwareCommand = new ParameterizedDelegateCommand<HostSoftwareDiscoveryCandidateRecord>(
            candidate => _ = ConfirmHostSoftwareAsync(candidate),
            CanDecideHostSoftware);
        rejectHostSoftwareCommand = new ParameterizedDelegateCommand<HostSoftwareDiscoveryCandidateRecord>(
            candidate => _ = RejectHostSoftwareAsync(candidate),
            CanDecideHostSoftware);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand StartCommand => startCommand;
    public ICommand StopCommand => stopCommand;
    public ICommand ConfirmDetectionCommand => confirmDetectionCommand;
    public ICommand ConfirmDatabaseCommand => confirmDatabaseCommand;
    public ICommand ConfirmHostSoftwareCommand => confirmHostSoftwareCommand;
    public ICommand RejectHostSoftwareCommand => rejectHostSoftwareCommand;
    public CollectionViewModelState State => state;
    public IReadOnlyList<DetectionCandidate> DetectionCandidates => detectionCandidates;
    public IReadOnlyList<DatabaseInstanceCandidate> DatabaseCandidates => databaseCandidates;
    public IReadOnlyList<HostSoftwareDiscoveryCandidateRecord> HostSoftwareCandidates => hostSoftwareCandidates;
    public IReadOnlyList<CompletedCollectionCommand> CompletedCommands => completedCommands;
    public IReadOnlyList<CollectionAdapterOption> AdapterOptions => adapterOptions;
    public CollectionAdapterOption? SelectedAdapterOption
    {
        get => selectedAdapterOption;
        set
        {
            EnsureSelectionCanChange();
            var selected = value == null
                ? null
                : adapterOptions.FirstOrDefault(option => option.Id == value.Id)
                    ?? throw new ArgumentException("所选采集适配器不适用于当前设备。", nameof(value));
            if (ReferenceEquals(selectedAdapterOption, selected))
            {
                return;
            }

            selectedAdapterOption = selected;
            OnPropertyChanged();
            OnPropertyChanged(nameof(AdapterScopeNotice));
            RefreshReadiness();
        }
    }
    public bool IsAdapterSelectionVisible => adapterOptions.Count > 0;
    public string AdapterScopeNotice => selectedAdapterOption?.ScopeNotice
        ?? (IsAdapterSelectionVisible
            ? "必须明确选择与实际系统或厂商一致的已验证适配器，未选择时不会连接或执行命令。"
            : string.Empty);
    public DatabaseInstanceCandidate? SelectedDatabaseCandidate => selectedDatabaseCandidate;
    public CollectionState? ProgressState => progressState;
    public string ProgressMessage => progressMessage;
    public string? CurrentCommand => currentCommand;
    public int CompletedCommandCount => completedCommandCount;
    public int TotalCommandCount => totalCommandCount;
    public CollectionError? Error => error;
    public bool IsDetectionConfirmationVisible => State == CollectionViewModelState.AwaitingConfirmation;
    public bool IsRecoveredIdentification => isRecoveredIdentification;
    public bool IsDatabaseConfirmationVisible =>
        (State == CollectionViewModelState.AwaitingDatabaseConfirmation
            || State == CollectionViewModelState.ConfirmingDatabase)
        && HostSoftwareCandidates.Count == 0;
    public bool IsHostSoftwareConfirmationVisible =>
        (State == CollectionViewModelState.AwaitingDatabaseConfirmation
            || State == CollectionViewModelState.ConfirmingDatabase)
        && HostSoftwareCandidates.Count != 0;
    public bool IsComponentCenterNavigationSuggested =>
        selectedDevice != null && !IsRequiredComponentAvailable;

    public void SelectProject(ProjectRecord project)
    {
        EnsureSelectionCanChange();
        var nextProject = project ?? throw new ArgumentNullException(nameof(project));
        if (selectedProject == null || !selectedProject.Id.Equals(nextProject.Id))
        {
            selectedDevice = null;
            ConfigureAdapterSelection(null);
            ClearPendingIdentification();
            ClearDeviceTransientState();
            OnPropertyChanged(nameof(IsComponentCenterNavigationSuggested));
        }

        selectedProject = nextProject;
        RefreshReadiness();
    }

    public void SelectDevice(CollectionDeviceSelection deviceSelection)
    {
        EnsureSelectionCanChange();
        var nextSelection = deviceSelection ?? throw new ArgumentNullException(nameof(deviceSelection));
        var deviceChanged = selectedDevice == null
            || !selectedDevice.Device.Id.Equals(nextSelection.Device.Id);
        if (selectedDevice != null && deviceChanged)
        {
            ClearPendingIdentification();
            ClearDeviceTransientState();
        }

        var isRestoredPendingDevice = pendingIdentificationBatchId.HasValue
            && pendingIdentificationDeviceId.Equals(nextSelection.Device.Id);
        if (deviceChanged && !isRestoredPendingDevice)
        {
            selectedAdapterOption = null;
        }

        selectedDevice = nextSelection;
        ConfigureAdapterSelection(nextSelection.Device.Category);
        OnPropertyChanged(nameof(IsComponentCenterNavigationSuggested));
        if (pendingIdentificationBatchId.HasValue
            && pendingIdentificationDeviceId.Equals(selectedDevice.Device.Id))
        {
            SetState(CollectionViewModelState.AwaitingConfirmation);
        }
        else if (pendingHostSoftwareBatchId.HasValue
            && pendingHostSoftwareDeviceId.Equals(selectedDevice.Device.Id))
        {
            SetState(CollectionViewModelState.AwaitingDatabaseConfirmation);
        }
        else
        {
            RefreshReadiness();
        }
    }

    public void ClearDeviceSelection()
    {
        EnsureSelectionCanChange();
        selectedDevice = null;
        ConfigureAdapterSelection(null);
        ClearPendingIdentification();
        ClearDeviceTransientState();
        OnPropertyChanged(nameof(IsComponentCenterNavigationSuggested));
        RefreshReadiness();
    }

    public void SetRequiredComponentAvailability(bool isAvailable)
    {
        requiredComponentAvailabilityOverride = isAvailable;
        OnPropertyChanged(nameof(IsComponentCenterNavigationSuggested));
        RefreshReadiness();
    }

    public async Task RestorePendingIdentificationAsync(DeviceRecord device)
    {
        if (device == null)
        {
            throw new ArgumentNullException(nameof(device));
        }

        var generation = unchecked(++pendingIdentificationLoadGeneration);
        if (selectedProject == null
            || !device.ProjectId.Equals(selectedProject.Id))
        {
            return;
        }

        if (pendingIdentificationRepository == null)
        {
            await RestorePendingHostSoftwareAsync(device, generation).ConfigureAwait(true);
            return;
        }

        isRestoringIdentification = true;
        progressMessage = "正在检查当前设备是否存在上次待确认的识别结果。";
        OnPropertyChanged(nameof(ProgressMessage));
        SetState(CollectionViewModelState.RestoringIdentification);

        try
        {
            var restored = await pendingIdentificationRepository
                .GetLatestPendingDeviceIdentificationAsync(device.Id)
                .ConfigureAwait(true);
            if (generation != pendingIdentificationLoadGeneration
                || selectedProject == null
                || !device.ProjectId.Equals(selectedProject.Id)
                || (selectedDevice != null && !selectedDevice.Device.Id.Equals(device.Id)))
            {
                return;
            }

            isRestoringIdentification = false;

            if (restored == null)
            {
                ClearPendingIdentification();
                await RestorePendingHostSoftwareAsync(
                    device,
                    pendingIdentificationLoadGeneration).ConfigureAwait(true);
                return;
            }

            ClearPendingHostSoftware();
            pendingIdentificationBatchId = restored.BatchId;
            pendingIdentificationDeviceId = restored.DeviceId;
            isRecoveredIdentification = true;
            OnPropertyChanged(nameof(IsRecoveredIdentification));
            SetDetectionCandidates(restored.Candidates);
            SelectAdapterForRestoredCandidates(device.Category, restored.Candidates);
            progressMessage = "已恢复上次待确认的设备识别候选；确认后会重新执行低风险识别，不会直接使用旧结果采集。";
            OnPropertyChanged(nameof(ProgressMessage));
            SetState(CollectionViewModelState.AwaitingConfirmation);
        }
        catch (Exception exception)
        {
            if (generation != pendingIdentificationLoadGeneration)
            {
                return;
            }

            isRestoringIdentification = false;
            ClearPendingIdentification();
            SetError(new CollectionError(
                "待确认识别候选读取失败",
                "本地项目数据库无法读取上次保存的候选批次",
                "检查本地数据目录权限和磁盘状态后重新选择设备",
                exception.GetType().Name));
            RefreshReadiness();
        }
    }

    private async Task RestorePendingHostSoftwareAsync(DeviceRecord device, int generation)
    {
        if (pendingHostSoftwareRepository == null)
        {
            isRestoringIdentification = false;
            ClearPendingHostSoftware();
            RefreshReadiness();
            return;
        }

        isRestoringIdentification = true;
        progressMessage = "正在检查当前设备是否存在上次待确认的数据库或中间件结果。";
        OnPropertyChanged(nameof(ProgressMessage));
        SetState(CollectionViewModelState.RestoringIdentification);
        try
        {
            var restored = await pendingHostSoftwareRepository
                .GetLatestPendingHostSoftwareDiscoveryBatchAsync(device.Id)
                .ConfigureAwait(true);
            if (generation != pendingIdentificationLoadGeneration
                || selectedProject == null
                || !device.ProjectId.Equals(selectedProject.Id)
                || (selectedDevice != null && !selectedDevice.Device.Id.Equals(device.Id)))
            {
                return;
            }

            isRestoringIdentification = false;
            if (restored == null)
            {
                ClearPendingHostSoftware();
                RefreshReadiness();
                return;
            }

            pendingHostSoftwareBatchId = restored.Batch.BatchId;
            pendingHostSoftwareDeviceId = restored.Batch.DeviceId;
            SetHostSoftwareCandidates(restored.PendingCandidates);
            progressMessage = "已恢复上次待确认的数据库或中间件候选；旧证据保持不变，可继续逐项确认或排除。";
            OnPropertyChanged(nameof(ProgressMessage));
            SetState(CollectionViewModelState.AwaitingDatabaseConfirmation);
        }
        catch (Exception exception)
        {
            if (generation != pendingIdentificationLoadGeneration)
            {
                return;
            }

            isRestoringIdentification = false;
            ClearPendingHostSoftware();
            SetError(new CollectionError(
                "待确认主机软件候选读取失败",
                "本地项目数据库无法读取上次保存的数据库或中间件候选",
                "检查本地数据目录权限和磁盘状态后重新选择设备",
                exception.GetType().Name));
            RefreshReadiness();
        }
    }

    public Task StartAsync()
    {
        if (!CanStart())
        {
            throw new InvalidOperationException("项目、设备、连接组件和主机指纹均就绪后才能开始采集。");
        }

        return RunAsync(null, null);
    }

    public Task ConfirmAndRetryAsync(DetectionCandidate candidate)
    {
        if (candidate == null)
        {
            throw new ArgumentNullException(nameof(candidate));
        }

        if (State != CollectionViewModelState.AwaitingConfirmation
            || !DetectionCandidates.Contains(candidate)
            || !pendingIdentificationBatchId.HasValue
            || !CanConfirmDetection(candidate))
        {
            throw new InvalidOperationException("只能在连接和组件就绪后确认当前识别候选项。");
        }

        return RunAsync(candidate, pendingIdentificationBatchId.Value);
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
            var remainingCandidates = DatabaseCandidates
                .Where(item => !ReferenceEquals(item, candidate))
                .ToArray();
            SetDatabaseCandidates(remainingCandidates);
            if (remainingCandidates.Length == 0)
            {
                progressMessage = "所有发现的数据库实例均已完成人工确认。";
                OnPropertyChanged(nameof(ProgressMessage));
                SetState(CollectionViewModelState.DatabaseConfirmed);
            }
            else
            {
                progressMessage = "已保存一个数据库实例的人工确认，仍有 "
                    + remainingCandidates.Length
                    + " 个候选需要处理。";
                OnPropertyChanged(nameof(ProgressMessage));
                SetState(CollectionViewModelState.AwaitingDatabaseConfirmation);
            }
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

    public Task ConfirmHostSoftwareAsync(HostSoftwareDiscoveryCandidateRecord candidate)
    {
        return DecideHostSoftwareAsync(candidate, true);
    }

    public Task RejectHostSoftwareAsync(HostSoftwareDiscoveryCandidateRecord candidate)
    {
        return DecideHostSoftwareAsync(candidate, false);
    }

    private async Task DecideHostSoftwareAsync(
        HostSoftwareDiscoveryCandidateRecord candidate,
        bool confirm)
    {
        if (candidate == null)
        {
            throw new ArgumentNullException(nameof(candidate));
        }

        if (!CanDecideHostSoftware(candidate)
            || !pendingHostSoftwareBatchId.HasValue
            || candidate.BatchId != pendingHostSoftwareBatchId.Value
            || hostSoftwareConfirmationService == null)
        {
            throw new InvalidOperationException("只能处理当前设备待确认的数据库或中间件候选。");
        }

        SetError(null);
        SetState(CollectionViewModelState.ConfirmingDatabase);
        try
        {
            if (confirm)
            {
                await hostSoftwareConfirmationService
                    .ConfirmAsync(candidate, CancellationToken.None)
                    .ConfigureAwait(true);
            }
            else
            {
                await hostSoftwareConfirmationService
                    .RejectAsync(
                        candidate,
                        "测评人员在候选界面标记为不是本次测评目标实例。",
                        CancellationToken.None)
                    .ConfigureAwait(true);
            }

            var remaining = HostSoftwareCandidates
                .Where(item => item.CandidateId != candidate.CandidateId)
                .ToArray();
            SetHostSoftwareCandidates(remaining);
            if (remaining.Length == 0)
            {
                pendingHostSoftwareBatchId = null;
                pendingHostSoftwareDeviceId = default(DeviceId);
                progressMessage = "所有发现的数据库和中间件候选均已完成人工处理。";
                OnPropertyChanged(nameof(ProgressMessage));
                SetState(CollectionViewModelState.DatabaseConfirmed);
            }
            else
            {
                progressMessage = (confirm ? "已确认" : "已排除")
                    + "一个候选，仍有 " + remaining.Length + " 个需要处理。";
                OnPropertyChanged(nameof(ProgressMessage));
                SetState(CollectionViewModelState.AwaitingDatabaseConfirmation);
            }
        }
        catch (Exception exception)
        {
            SetError(new CollectionError(
                "主机软件候选处理失败",
                "本地项目数据库无法保存本次人工决议",
                "检查本地数据目录权限和磁盘空间后重试",
                exception.GetType().Name));
            SetState(CollectionViewModelState.AwaitingDatabaseConfirmation);
        }
    }

    private bool CanStart()
    {
        return State != CollectionViewModelState.Running
            && State != CollectionViewModelState.Stopping
            && State != CollectionViewModelState.RestoringIdentification
            && State != CollectionViewModelState.AwaitingConfirmation
            && State != CollectionViewModelState.AwaitingDatabaseConfirmation
            && State != CollectionViewModelState.ConfirmingDatabase
            && HasReadySelection;
    }

    private bool HasReadySelection =>
        selectedProject != null
        && selectedDevice != null
        && selectedAdapterOption != null
        && selectedDevice.Device.ProjectId.Equals(selectedProject.Id)
        && IsRequiredComponentAvailable
        && selectedDevice.IsHostKeyTrusted;

    private bool CanConfirmDetection(DetectionCandidate? candidate)
    {
        return candidate != null
            && State == CollectionViewModelState.AwaitingConfirmation
            && DetectionCandidates.Contains(candidate)
            && pendingIdentificationBatchId.HasValue
            && selectedProject != null
            && selectedDevice != null
            && selectedDevice.Device.ProjectId.Equals(selectedProject.Id)
            && selectedDevice.Device.Id.Equals(pendingIdentificationDeviceId)
            && selectedAdapterOption != null
            && IsRequiredComponentAvailable
            && selectedDevice.IsHostKeyTrusted;
    }

    private bool CanDecideHostSoftware(HostSoftwareDiscoveryCandidateRecord? candidate)
    {
        return candidate != null
            && State == CollectionViewModelState.AwaitingDatabaseConfirmation
            && HostSoftwareCandidates.Any(item => item.CandidateId == candidate.CandidateId)
            && pendingHostSoftwareBatchId.HasValue
            && candidate.BatchId == pendingHostSoftwareBatchId.Value
            && selectedDevice != null
            && selectedDevice.Device.Id.Equals(pendingHostSoftwareDeviceId)
            && hostSoftwareConfirmationService != null;
    }

    private bool IsRequiredComponentAvailable =>
        requiredComponentAvailabilityOverride
        ?? selectedDevice?.IsRequiredComponentAvailable
        ?? false;

    private async Task RunAsync(
        DetectionCandidate? confirmedCandidate,
        Guid? confirmationBatchId)
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
            ClearPendingHostSoftware();
            if (confirmationBatchId.HasValue && isRecoveredIdentification)
            {
                isRecoveredIdentification = false;
                OnPropertyChanged(nameof(IsRecoveredIdentification));
            }
            selectedDatabaseCandidate = null;
            OnPropertyChanged(nameof(SelectedDatabaseCandidate));
            SetState(CollectionViewModelState.Running);

            try
            {
                var request = new CollectionWorkflowRequest(
                    selectedProject,
                    selectedDevice,
                    selectedAdapterOption?.Id
                        ?? throw new InvalidOperationException("尚未选择采集适配器。"),
                    confirmedCandidate,
                    confirmationBatchId);
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
                    ClearPendingHostSoftware();
                    if (confirmationBatchId.HasValue)
                    {
                        await RestorePendingIdentificationAsync(selectedDevice.Device);
                    }
                    else
                    {
                        SetState(CollectionViewModelState.Stopped);
                    }
                }
                else
                {
                    Apply(result);
                    if (confirmationBatchId.HasValue
                        && result.Outcome == CollectionWorkflowOutcome.Failed)
                    {
                        await RestorePendingIdentificationAsync(selectedDevice.Device);
                    }
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
                if (confirmationBatchId.HasValue)
                {
                    await RestorePendingIdentificationAsync(selectedDevice.Device);
                }
                else
                {
                    SetState(CollectionViewModelState.Stopped);
                }
            }
            catch (Exception exception)
            {
                if (cancellation.IsCancellationRequested)
                {
                    SetError(null);
                    if (confirmationBatchId.HasValue)
                    {
                        await RestorePendingIdentificationAsync(selectedDevice.Device);
                    }
                    else
                    {
                        SetState(CollectionViewModelState.Stopped);
                    }
                }
                else
                {
                    SetError(new CollectionError(
                        "采集任务失败",
                        "连接、组件或采集服务发生异常",
                        "检查组件中心和设备连接后重试",
                        exception.GetType().Name));
                    SetState(CollectionViewModelState.Failed);
                    if (confirmationBatchId.HasValue)
                    {
                        await RestorePendingIdentificationAsync(selectedDevice.Device);
                    }
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
                ClearPendingIdentification();
                SetState(CollectionViewModelState.Completed);
                break;
            case CollectionWorkflowOutcome.RequiresConfirmation:
                pendingIdentificationBatchId = result.PendingIdentificationBatchId
                    ?? throw new InvalidOperationException("待确认识别结果缺少持久化批次标识。");
                pendingIdentificationDeviceId = selectedDevice?.Device.Id ?? default(DeviceId);
                isRecoveredIdentification = false;
                OnPropertyChanged(nameof(IsRecoveredIdentification));
                SetDetectionCandidates(result.DetectionCandidates);
                SetState(CollectionViewModelState.AwaitingConfirmation);
                break;
            case CollectionWorkflowOutcome.RequiresDatabaseConfirmation:
                ClearPendingIdentification();
                SetDatabaseCandidates(result.DatabaseCandidates);
                SetState(CollectionViewModelState.AwaitingDatabaseConfirmation);
                break;
            case CollectionWorkflowOutcome.RequiresHostSoftwareConfirmation:
                ClearPendingIdentification();
                pendingHostSoftwareBatchId = result.PendingHostSoftwareBatchId
                    ?? throw new InvalidOperationException("待确认主机软件结果缺少持久化批次标识。");
                pendingHostSoftwareDeviceId = selectedDevice?.Device.Id ?? default(DeviceId);
                SetHostSoftwareCandidates(result.HostSoftwareCandidates);
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
            SetState(isRestoringIdentification
                ? CollectionViewModelState.RestoringIdentification
                : pendingIdentificationBatchId.HasValue
                ? CollectionViewModelState.AwaitingConfirmation
                : pendingHostSoftwareBatchId.HasValue
                ? CollectionViewModelState.AwaitingDatabaseConfirmation
                : HasReadySelection
                    ? CollectionViewModelState.Ready
                    : CollectionViewModelState.Idle);
        }

        RaiseCommandStates();
    }

    private void ConfigureAdapterSelection(TargetCategory? category)
    {
        IReadOnlyList<CollectionAdapterOption> nextOptions;
        CollectionAdapterOption? nextSelection;
        switch (category)
        {
            case TargetCategory.Automatic:
            case TargetCategory.Server:
                nextOptions = new[] { GenericLinuxAdapter, WindowsServerSshAdapter };
                nextSelection = selectedAdapterOption?.Id == CollectionAdapterId.GenericLinux
                    ? GenericLinuxAdapter
                    : selectedAdapterOption?.Id == CollectionAdapterId.WindowsServerSsh
                        ? WindowsServerSshAdapter
                        : null;
                break;
            case TargetCategory.NetworkDevice:
                nextOptions = new[] { HuaweiVrpAdapter, H3cComwareAdapter };
                nextSelection = selectedAdapterOption?.Id == CollectionAdapterId.HuaweiVrp
                    ? HuaweiVrpAdapter
                    : selectedAdapterOption?.Id == CollectionAdapterId.H3cComware
                        ? H3cComwareAdapter
                        : null;
                break;
            case TargetCategory.Middleware:
                nextOptions = new[] { NginxLinuxSshAdapter };
                nextSelection = selectedAdapterOption?.Id == CollectionAdapterId.NginxLinuxSsh
                    ? NginxLinuxSshAdapter
                    : null;
                break;
            default:
                nextOptions = Array.Empty<CollectionAdapterOption>();
                nextSelection = null;
                break;
        }

        adapterOptions = nextOptions;
        selectedAdapterOption = nextSelection;
        OnPropertyChanged(nameof(AdapterOptions));
        OnPropertyChanged(nameof(SelectedAdapterOption));
        OnPropertyChanged(nameof(IsAdapterSelectionVisible));
        OnPropertyChanged(nameof(AdapterScopeNotice));
    }

    private void SelectAdapterForRestoredCandidates(
        TargetCategory category,
        IReadOnlyList<DetectionCandidate> candidates)
    {
        if (selectedAdapterOption != null)
        {
            return;
        }

        if (category == TargetCategory.NetworkDevice)
        {
            selectedAdapterOption = candidates.Any(candidate =>
                    string.Equals(candidate.Vendor, "Huawei", StringComparison.OrdinalIgnoreCase))
                ? HuaweiVrpAdapter
                : candidates.Any(candidate =>
                    string.Equals(candidate.Vendor, "H3C", StringComparison.OrdinalIgnoreCase)
                    && string.Equals(candidate.ProductFamily, "Comware", StringComparison.OrdinalIgnoreCase))
                    ? H3cComwareAdapter
                    : null;
        }
        else if (category == TargetCategory.Automatic || category == TargetCategory.Server)
        {
            selectedAdapterOption = candidates.Any(candidate =>
                    string.Equals(candidate.Vendor, "Microsoft", StringComparison.OrdinalIgnoreCase)
                    && string.Equals(candidate.ProductFamily, "Windows Server", StringComparison.OrdinalIgnoreCase))
                ? WindowsServerSshAdapter
                : candidates.Any(candidate =>
                    candidate.Category == TargetCategory.Server
                    && !string.Equals(candidate.Vendor, "Microsoft", StringComparison.OrdinalIgnoreCase))
                    ? GenericLinuxAdapter
                    : null;
        }
        else if (category == TargetCategory.Middleware)
        {
            selectedAdapterOption = candidates.Any(candidate =>
                    string.Equals(candidate.Vendor, "NGINX", StringComparison.OrdinalIgnoreCase)
                    && string.Equals(candidate.ProductFamily, "Nginx", StringComparison.OrdinalIgnoreCase))
                ? NginxLinuxSshAdapter
                : null;
        }

        if (selectedAdapterOption == null)
        {
            return;
        }

        OnPropertyChanged(nameof(SelectedAdapterOption));
        OnPropertyChanged(nameof(AdapterScopeNotice));
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
        OnPropertyChanged(nameof(IsHostSoftwareConfirmationVisible));
        RaiseCommandStates();
    }

    private void SetDetectionCandidates(IEnumerable<DetectionCandidate> candidates)
    {
        detectionCandidates = new ReadOnlyCollection<DetectionCandidate>(candidates.ToArray());
        OnPropertyChanged(nameof(DetectionCandidates));
    }

    private void ClearPendingIdentification()
    {
        unchecked { pendingIdentificationLoadGeneration++; }
        isRestoringIdentification = false;
        pendingIdentificationBatchId = null;
        pendingIdentificationDeviceId = default(DeviceId);
        if (isRecoveredIdentification)
        {
            isRecoveredIdentification = false;
            OnPropertyChanged(nameof(IsRecoveredIdentification));
        }

        SetDetectionCandidates(Array.Empty<DetectionCandidate>());
    }

    private void ClearDeviceTransientState()
    {
        progressState = null;
        progressMessage = string.Empty;
        currentCommand = null;
        completedCommandCount = 0;
        totalCommandCount = 0;
        selectedDatabaseCandidate = null;
        SetCompletedCommands(Array.Empty<CompletedCollectionCommand>());
        SetDatabaseCandidates(Array.Empty<DatabaseInstanceCandidate>());
        ClearPendingHostSoftware();
        SetError(null);
        OnPropertyChanged(nameof(ProgressState));
        OnPropertyChanged(nameof(ProgressMessage));
        OnPropertyChanged(nameof(CurrentCommand));
        OnPropertyChanged(nameof(CompletedCommandCount));
        OnPropertyChanged(nameof(TotalCommandCount));
        OnPropertyChanged(nameof(SelectedDatabaseCandidate));
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

    private void SetHostSoftwareCandidates(
        IEnumerable<HostSoftwareDiscoveryCandidateRecord> candidates)
    {
        hostSoftwareCandidates = new ReadOnlyCollection<HostSoftwareDiscoveryCandidateRecord>(
            candidates.ToArray());
        OnPropertyChanged(nameof(HostSoftwareCandidates));
        OnPropertyChanged(nameof(IsDatabaseConfirmationVisible));
        OnPropertyChanged(nameof(IsHostSoftwareConfirmationVisible));
    }

    private void ClearPendingHostSoftware()
    {
        pendingHostSoftwareBatchId = null;
        pendingHostSoftwareDeviceId = default(DeviceId);
        SetHostSoftwareCandidates(Array.Empty<HostSoftwareDiscoveryCandidateRecord>());
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
        confirmHostSoftwareCommand.RaiseCanExecuteChanged();
        rejectHostSoftwareCommand.RaiseCanExecuteChanged();
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
