using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Sessions;

namespace AssessmentTool.App.ViewModels;

public enum DeviceConnectionViewModelState
{
    NoDevice,
    LoadingTrust,
    ReadyToProbe,
    Probing,
    AwaitingConfirmation,
    TestingLogin,
    Succeeded,
    Blocked,
    Failed
}

public sealed class DeviceConnectionViewModel : INotifyPropertyChanged
{
    private readonly ISshConnectionWorkflowService? service;
    private DeviceRecord? device;
    private DeviceConnectionViewModelState state = DeviceConnectionViewModelState.NoDevice;
    private string statusMessage = "请选择设备后进行安全连接测试。";
    private string algorithm = string.Empty;
    private string fingerprint = string.Empty;
    private string technicalDetails = string.Empty;
    private HostKeyTrust? currentTrust;
    private CancellationTokenSource? selectionCancellation;
    private int selectionGeneration;

    public DeviceConnectionViewModel(ISshConnectionWorkflowService? service)
    {
        this.service = service;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public DeviceRecord? Device => device;
    public DeviceConnectionViewModelState State => state;
    public string StatusMessage => statusMessage;
    public string Algorithm => algorithm;
    public string Fingerprint => fingerprint;
    public string TechnicalDetails => technicalDetails;
    public HostKeyTrust? CurrentTrust => currentTrust;
    public bool CanProbe => service != null && device != null
        && state != DeviceConnectionViewModelState.LoadingTrust
        && state != DeviceConnectionViewModelState.Probing
        && state != DeviceConnectionViewModelState.TestingLogin;
    public bool CanConfirm => service != null && device != null
        && state == DeviceConnectionViewModelState.AwaitingConfirmation;

    public async Task SelectDeviceAsync(DeviceRecord? value)
    {
        var generation = unchecked(++selectionGeneration);
        selectionCancellation?.Cancel();
        selectionCancellation = value == null || service == null
            ? null
            : new CancellationTokenSource();
        device = value;
        algorithm = string.Empty;
        fingerprint = string.Empty;
        technicalDetails = string.Empty;
        currentTrust = null;
        if (device == null)
        {
            SetState(DeviceConnectionViewModelState.NoDevice, "请选择设备后进行安全连接测试。");
        }
        else if (service == null)
        {
            SetState(DeviceConnectionViewModelState.Failed, "安全连接服务尚未初始化。");
        }
        else
        {
            var selectedDevice = device;
            var cancellationToken = selectionCancellation!.Token;
            SetState(DeviceConnectionViewModelState.LoadingTrust, "正在读取当前设备已保存的 SSH 指纹状态。");
            try
            {
                var trust = await service.GetTrustAsync(selectedDevice, cancellationToken);
                if (!IsCurrent(generation, selectedDevice))
                {
                    return;
                }

                EnsureResultDevice(trust.DeviceId, selectedDevice);
                ApplyTrust(trust.Trust);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                if (IsCurrent(generation, selectedDevice))
                {
                    SetFailure("无法读取设备指纹状态，请检查本地项目数据。", exception);
                }
            }
        }

        RaiseAll();
    }

    public async Task ProbeAsync()
    {
        if (!CanProbe || device == null || service == null || selectionCancellation == null)
        {
            return;
        }

        var generation = selectionGeneration;
        var selectedDevice = device;
        var cancellationToken = selectionCancellation.Token;
        SetState(DeviceConnectionViewModelState.Probing, "正在读取 SSH 主机指纹；不会读取密码或执行命令。");
        try
        {
            var result = await service.ProbeAsync(selectedDevice, cancellationToken);
            if (!IsCurrent(generation, selectedDevice))
            {
                return;
            }

            EnsureResultDevice(result.TrustRecord.DeviceId, selectedDevice);
            ApplyResult(result);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            if (IsCurrent(generation, selectedDevice))
            {
                SetFailure("SSH 主机指纹探测失败。", exception);
            }
        }
    }

    public async Task ConfirmAndTestAsync()
    {
        if (!CanConfirm || device == null || service == null || selectionCancellation == null)
        {
            return;
        }

        var generation = selectionGeneration;
        var selectedDevice = device;
        var cancellationToken = selectionCancellation.Token;
        SetState(DeviceConnectionViewModelState.TestingLogin, "正在复核指纹并进行无命令登录测试。");
        try
        {
            var result = await service.ConfirmAndTestAsync(selectedDevice, cancellationToken);
            if (!IsCurrent(generation, selectedDevice))
            {
                return;
            }

            EnsureResultDevice(result.TrustRecord.DeviceId, selectedDevice);
            ApplyResult(result);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            if (IsCurrent(generation, selectedDevice))
            {
                SetFailure("SSH 登录测试失败，未执行任何客户设备命令。", exception);
            }
        }
    }

    private bool IsCurrent(int generation, DeviceRecord selectedDevice)
    {
        return generation == selectionGeneration
            && device != null
            && device.Id.Equals(selectedDevice.Id);
    }

    private static void EnsureResultDevice(DeviceId resultDeviceId, DeviceRecord selectedDevice)
    {
        if (!resultDeviceId.Equals(selectedDevice.Id))
        {
            throw new InvalidOperationException("安全连接结果不属于当前设备，已阻止显示。");
        }
    }

    private void ApplyResult(SshConnectionWorkflowResult result)
    {
        currentTrust = result.TrustRecord.Trust;
        algorithm = result.TrustRecord.Trust.ObservedAlgorithm
            ?? result.TrustRecord.Trust.Algorithm
            ?? result.ConnectionResult.Algorithm
            ?? string.Empty;
        fingerprint = result.TrustRecord.Trust.ObservedFingerprint
            ?? result.TrustRecord.Trust.Fingerprint
            ?? result.ConnectionResult.Fingerprint
            ?? string.Empty;
        technicalDetails = string.Empty;
        if (result.ConnectionResult.Outcome == SshConnectionTestOutcome.Succeeded)
        {
            SetState(DeviceConnectionViewModelState.Succeeded, result.ConnectionResult.UserMessage);
        }
        else if (result.TrustRecord.Trust.State == HostKeyTrustState.AwaitingConfirmation)
        {
            SetState(DeviceConnectionViewModelState.AwaitingConfirmation, result.ConnectionResult.UserMessage);
        }
        else if (result.TrustRecord.Trust.State == HostKeyTrustState.MismatchBlocked)
        {
            SetState(DeviceConnectionViewModelState.Blocked, result.ConnectionResult.UserMessage);
        }
        else if (result.ConnectionResult.Outcome == SshConnectionTestOutcome.HostKeyRejected)
        {
            SetState(DeviceConnectionViewModelState.Blocked, result.ConnectionResult.UserMessage);
        }
        else
        {
            SetState(DeviceConnectionViewModelState.Failed, result.ConnectionResult.UserMessage);
        }

        RaiseAll();
    }

    private void ApplyTrust(HostKeyTrust trust)
    {
        currentTrust = trust;
        algorithm = trust.ObservedAlgorithm ?? trust.Algorithm ?? string.Empty;
        fingerprint = trust.ObservedFingerprint ?? trust.Fingerprint ?? string.Empty;
        if (trust.State == HostKeyTrustState.AwaitingConfirmation)
        {
            SetState(DeviceConnectionViewModelState.AwaitingConfirmation, "请核对完整主机指纹；确认后才会读取密码进行登录测试。");
        }
        else if (trust.State == HostKeyTrustState.Verified || trust.State == HostKeyTrustState.Pinned)
        {
            SetState(DeviceConnectionViewModelState.ReadyToProbe, "主机指纹已保存。可重新探测并进行连接测试。");
        }
        else if (trust.State == HostKeyTrustState.MismatchBlocked)
        {
            SetState(DeviceConnectionViewModelState.Blocked, "主机指纹发生变化，已阻止自动登录，需要人工重新核对。");
        }
        else
        {
            SetState(DeviceConnectionViewModelState.ReadyToProbe, "尚未读取主机指纹。首次测试不会使用密码。");
        }
    }

    private void SetFailure(string message, Exception exception)
    {
        technicalDetails = exception.GetType().Name;
        SetState(DeviceConnectionViewModelState.Failed, message);
    }

    private void SetState(DeviceConnectionViewModelState value, string message)
    {
        state = value;
        statusMessage = message;
        RaiseAll();
    }

    private void RaiseAll()
    {
        OnPropertyChanged(nameof(Device));
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(StatusMessage));
        OnPropertyChanged(nameof(Algorithm));
        OnPropertyChanged(nameof(Fingerprint));
        OnPropertyChanged(nameof(TechnicalDetails));
        OnPropertyChanged(nameof(CurrentTrust));
        OnPropertyChanged(nameof(CanProbe));
        OnPropertyChanged(nameof(CanConfirm));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
