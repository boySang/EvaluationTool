using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows.Input;
using AssessmentTool.App.Services;
using AssessmentTool.Windows.Components;

namespace AssessmentTool.App.ViewModels;

public enum ComponentCenterState
{
    NotChecked,
    Refreshing,
    PreparingInstall,
    Installing,
    Ready,
    Failed
}

public enum ComponentItemState
{
    Available,
    Missing,
    Invalid,
    CheckFailed
}

public sealed class ComponentCenterViewModel : INotifyPropertyChanged
{
    private const string InitialImpact = "尚未检测 Plink 连接组件，SSH连接暂不可用；项目、设备和其他功能仍可使用。";
    private const string InitialInstructions = "请单击“重新检测”。软件只检查程序固定目录中的可信组件，不会扫描其他目录。";
    private readonly object refreshSync = new object();
    private readonly IComponentStatusService service;
    private readonly DelegateCommand refreshCommand;
    private Task? activeRefresh;
    private ComponentCenterState state = ComponentCenterState.NotChecked;
    private ComponentItemState componentState = ComponentItemState.Missing;
    private string userImpact = InitialImpact;
    private string offlineInstructions = InitialInstructions;
    private ComponentInstallPreview? preparedInstall;
    private string installStatusMessage = "尚未选择离线组件。";

    public ComponentCenterViewModel(IComponentStatusService service)
    {
        this.service = service ?? throw new ArgumentNullException(nameof(service));
        refreshCommand = new DelegateCommand(
            () => _ = RefreshAsync(),
            () => State != ComponentCenterState.Refreshing
                && State != ComponentCenterState.PreparingInstall
                && State != ComponentCenterState.Installing);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand RefreshCommand => refreshCommand;
    public ComponentCenterState State => state;
    public ComponentItemState ComponentState => componentState;
    public bool IsSshAvailable => State != ComponentCenterState.Failed
        && ComponentState == ComponentItemState.Available;
    public string StatusText
    {
        get
        {
            if (State == ComponentCenterState.NotChecked)
            {
                return "状态：尚未检测";
            }

            if (State == ComponentCenterState.Refreshing)
            {
                return "状态：正在检测（保留上次检测结果）";
            }

            if (State == ComponentCenterState.PreparingInstall)
            {
                return "状态：正在校验离线组件";
            }

            if (State == ComponentCenterState.Installing)
            {
                return "状态：正在安装并复核";
            }

            if (State == ComponentCenterState.Failed)
            {
                return "状态：检测失败";
            }

            switch (ComponentState)
            {
                case ComponentItemState.Available:
                    return "状态：可用";
                case ComponentItemState.Missing:
                    return "状态：缺失";
                case ComponentItemState.Invalid:
                    return "状态：组件无效";
                default:
                    return "状态：检查失败";
            }
        }
    }

    public string UserImpact => userImpact;
    public string OfflineInstructions => offlineInstructions;
    public string ComponentName => "Plink 连接组件";
    public string Source => "PuTTY 官方 0.84 x64（构建时验证签名与 SHA-256）";
    public string Size => "约 1.0 MB";
    public string NetworkRequirement => "正常使用无需联网；重新获取时需要联网";
    public string AdministratorRequirement => "不需要";
    public string RestartRequirement => "不需要";
    public string AutomaticActionNotice => "软件不会静默下载或安装；只有选择文件、通过固定哈希校验并再次确认后才会替换组件";
    public bool HasPreparedInstall => preparedInstall != null;
    public string PreparedInstallSummary => preparedInstall == null
        ? "尚未选择离线组件。"
        : preparedInstall.FileName
            + " · "
            + Math.Ceiling(preparedInstall.SizeBytes / 1024d).ToString("0")
            + " KB\nSHA-256："
            + preparedInstall.Sha256;
    public string InstallStatusMessage => installStatusMessage;

    public Task RefreshAsync()
    {
        lock (refreshSync)
        {
            if (State == ComponentCenterState.PreparingInstall
                || State == ComponentCenterState.Installing)
            {
                return Task.CompletedTask;
            }

            if (activeRefresh != null && !activeRefresh.IsCompleted)
            {
                return activeRefresh;
            }

            activeRefresh = RefreshCoreAsync();
            return activeRefresh;
        }
    }

    private async Task RefreshCoreAsync()
    {
        SetState(ComponentCenterState.Refreshing);
        try
        {
            var status = await service.GetPlinkStatusAsync();
            if (status == null)
            {
                throw new InvalidOperationException("组件检测服务未返回结果。");
            }

            ApplyStatus(status);
            SetState(ComponentCenterState.Ready);
        }
        catch (Exception)
        {
            componentState = ComponentItemState.CheckFailed;
            userImpact = "无法确认 Plink 组件是否可信，SSH连接保持禁用；项目、设备和其他功能仍可使用。";
            offlineInstructions = "请确认软件包完整、当前用户可读取“依赖组件”目录，然后重新检测。软件不会自动下载、安装或替换组件。";
            OnPropertyChanged(nameof(ComponentState));
            OnPropertyChanged(nameof(UserImpact));
            OnPropertyChanged(nameof(OfflineInstructions));
            SetState(ComponentCenterState.Failed);
        }
    }

    public async Task PrepareInstallAsync(string sourcePath)
    {
        if (State == ComponentCenterState.Refreshing
            || State == ComponentCenterState.PreparingInstall
            || State == ComponentCenterState.Installing)
        {
            return;
        }

        ClearPreparedInstall();
        installStatusMessage = "正在校验所选文件的来源固定哈希和大小。";
        OnPropertyChanged(nameof(InstallStatusMessage));
        SetState(ComponentCenterState.PreparingInstall);
        try
        {
            preparedInstall = await service.PreparePlinkInstallAsync(sourcePath);
            installStatusMessage = "离线组件已通过固定 SHA-256 校验，等待人工确认安装。";
            OnPropertyChanged(nameof(HasPreparedInstall));
            OnPropertyChanged(nameof(PreparedInstallSummary));
            OnPropertyChanged(nameof(InstallStatusMessage));
            SetState(ComponentCenterState.Ready);
        }
        catch (Exception exception)
        {
            installStatusMessage = "所选文件未通过可信组件校验，未复制或替换任何文件。技术信息："
                + exception.GetType().Name;
            OnPropertyChanged(nameof(InstallStatusMessage));
            SetState(ComponentCenterState.Ready);
        }
    }

    public async Task InstallPreparedAsync()
    {
        var preview = preparedInstall
            ?? throw new InvalidOperationException("尚未准备可安装的离线组件。");
        SetState(ComponentCenterState.Installing);
        installStatusMessage = "正在原子安装组件并执行安装后复核。";
        OnPropertyChanged(nameof(InstallStatusMessage));
        try
        {
            var status = await service.InstallPreparedPlinkAsync(preview);
            ApplyStatus(status);
            installStatusMessage = "Plink 已安装并通过 SHA-256、版本、架构和文件身份复核，SSH 功能已恢复。";
            ClearPreparedInstall();
            OnPropertyChanged(nameof(InstallStatusMessage));
            SetState(ComponentCenterState.Ready);
        }
        catch (Exception exception)
        {
            installStatusMessage = "组件安装失败，软件已尝试保留或恢复原文件。请重新解压完整软件包后重试。技术信息："
                + exception.GetType().Name;
            ClearPreparedInstall();
            OnPropertyChanged(nameof(InstallStatusMessage));
            SetState(ComponentCenterState.Failed);
        }
    }

    public void CancelPreparedInstall()
    {
        if (State == ComponentCenterState.Installing)
        {
            return;
        }

        ClearPreparedInstall();
        installStatusMessage = "已取消安装，未替换任何文件。";
        OnPropertyChanged(nameof(InstallStatusMessage));
    }

    private void ApplyStatus(ComponentStatus status)
    {
        componentState = Map(status.Failure);
        userImpact = status.UserImpact;
        offlineInstructions = status.OfflineInstructions;
        OnPropertyChanged(nameof(ComponentState));
        OnPropertyChanged(nameof(UserImpact));
        OnPropertyChanged(nameof(OfflineInstructions));
    }

    private void ClearPreparedInstall()
    {
        if (preparedInstall == null)
        {
            return;
        }

        preparedInstall = null;
        OnPropertyChanged(nameof(HasPreparedInstall));
        OnPropertyChanged(nameof(PreparedInstallSummary));
    }

    private static ComponentItemState Map(ComponentFailure failure)
    {
        switch (failure)
        {
            case ComponentFailure.None:
                return ComponentItemState.Available;
            case ComponentFailure.Missing:
                return ComponentItemState.Missing;
            case ComponentFailure.InspectionFailed:
                return ComponentItemState.CheckFailed;
            default:
                return ComponentItemState.Invalid;
        }
    }

    private void SetState(ComponentCenterState value)
    {
        if (state == value)
        {
            return;
        }

        state = value;
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(IsSshAvailable));
        refreshCommand.RaiseCanExecuteChanged();
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
