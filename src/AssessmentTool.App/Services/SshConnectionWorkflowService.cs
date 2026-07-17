using System;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Components;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Sessions;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public sealed class SshConnectionWorkflowService : ISshConnectionWorkflowService
{
    private readonly ISshHostKeyTrustRepository repository;
    private readonly SshConnectionTester tester;
    private readonly ComponentInspector componentInspector;

    public SshConnectionWorkflowService(
        ISshHostKeyTrustRepository repository,
        ICredentialVault credentialVault)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
        tester = new SshConnectionTester(
            credentialVault ?? throw new ArgumentNullException(nameof(credentialVault)));
        componentInspector = new ComponentInspector();
    }

    public Task<SshHostKeyTrustRecord> GetTrustAsync(
        DeviceRecord device,
        CancellationToken cancellationToken = default)
    {
        ValidateDevice(device);
        return repository.GetSshHostKeyTrustAsync(device.Id, cancellationToken);
    }

    public async Task<SshConnectionWorkflowResult> ProbeAsync(
        DeviceRecord device,
        CancellationToken cancellationToken = default)
    {
        ValidateDevice(device);
        var current = await repository.GetSshHostKeyTrustAsync(device.Id, cancellationToken);
        if (current.Trust.State == HostKeyTrustState.AwaitingConfirmation)
        {
            return new SshConnectionWorkflowResult(
                current,
                new SshConnectionTestResult(
                    SshConnectionTestOutcome.FingerprintFound,
                    "已有待确认的 SSH 主机指纹，请核对后确认。",
                    current.Trust.ObservedAlgorithm,
                    current.Trust.ObservedFingerprint));
        }

        SshConnectionTestResult observed;
        using (var candidate = CreatePlinkCandidate())
        {
            observed = await tester.ProbeHostKeyAsync(
                candidate, device.Host, device.Port, cancellationToken);
        }

        if (observed.Outcome != SshConnectionTestOutcome.FingerprintFound
            || observed.Algorithm == null
            || observed.Fingerprint == null)
        {
            return new SshConnectionWorkflowResult(current, observed);
        }

        var coordinator = HostKeyTrustServices.CreateCoordinator();
        HostKeyTrust nextTrust;
        if (current.Trust.State == HostKeyTrustState.Unconfigured)
        {
            nextTrust = coordinator.RecordObservation(
                coordinator.BeginProbe(current.Trust),
                observed.Algorithm,
                observed.Fingerprint,
                DateTimeOffset.UtcNow);
        }
        else if (current.Trust.IsEligibleForAutomaticConnection
            && string.Equals(current.Trust.Algorithm, observed.Algorithm, StringComparison.Ordinal)
            && string.Equals(current.Trust.Fingerprint, observed.Fingerprint, StringComparison.Ordinal))
        {
            nextTrust = coordinator.RecordMatchingObservation(current.Trust, DateTimeOffset.UtcNow);
        }
        else if (current.Trust.IsEligibleForAutomaticConnection)
        {
            nextTrust = coordinator.RecordMismatchObservation(
                current.Trust, observed.Algorithm, observed.Fingerprint, DateTimeOffset.UtcNow);
        }
        else
        {
            return new SshConnectionWorkflowResult(
                current,
                new SshConnectionTestResult(
                    SshConnectionTestOutcome.HostKeyRejected,
                    "当前指纹状态需要人工处理，已阻止自动登录。"));
        }

        var saved = await repository.SaveSshHostKeyTrustAsync(
            device.Id, nextTrust, current.Revision, cancellationToken);
        if (nextTrust.State == HostKeyTrustState.MismatchBlocked)
        {
            return new SshConnectionWorkflowResult(
                saved,
                new SshConnectionTestResult(
                    SshConnectionTestOutcome.HostKeyRejected,
                    "主机指纹与已确认值不一致，已在读取密码前阻止登录。"));
        }

        if (nextTrust.State == HostKeyTrustState.Verified)
        {
            using (var loginCandidate = CreatePlinkCandidate())
            {
                var login = await tester.TestLoginWithoutCommandAsync(
                    loginCandidate, CreateProfile(device, nextTrust), cancellationToken);
                return new SshConnectionWorkflowResult(saved, login);
            }
        }

        return new SshConnectionWorkflowResult(saved, observed);
    }

    public async Task<SshConnectionWorkflowResult> ConfirmAndTestAsync(
        DeviceRecord device,
        CancellationToken cancellationToken = default)
    {
        ValidateDevice(device);
        var current = await repository.GetSshHostKeyTrustAsync(device.Id, cancellationToken);
        if (current.Trust.State != HostKeyTrustState.AwaitingConfirmation)
        {
            return new SshConnectionWorkflowResult(
                current,
                new SshConnectionTestResult(
                    SshConnectionTestOutcome.HostKeyRejected,
                    "当前没有可确认的 SSH 主机指纹，请先重新探测。"));
        }

        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var pinned = coordinator.Confirm(current.Trust, DateTimeOffset.UtcNow, "测评人员在软件界面人工确认");
        var savedPinned = await repository.SaveSshHostKeyTrustAsync(
            device.Id, pinned, current.Revision, cancellationToken);

        SshConnectionTestResult reprobe;
        using (var probeCandidate = CreatePlinkCandidate())
        {
            reprobe = await tester.ProbeHostKeyAsync(
                probeCandidate, device.Host, device.Port, cancellationToken);
        }

        if (reprobe.Outcome != SshConnectionTestOutcome.FingerprintFound
            || reprobe.Algorithm == null
            || reprobe.Fingerprint == null)
        {
            return new SshConnectionWorkflowResult(savedPinned, reprobe);
        }

        if (!string.Equals(pinned.Algorithm, reprobe.Algorithm, StringComparison.Ordinal)
            || !string.Equals(pinned.Fingerprint, reprobe.Fingerprint, StringComparison.Ordinal))
        {
            var blocked = coordinator.RecordMismatchObservation(
                pinned, reprobe.Algorithm, reprobe.Fingerprint, DateTimeOffset.UtcNow);
            var savedBlocked = await repository.SaveSshHostKeyTrustAsync(
                device.Id, blocked, savedPinned.Revision, cancellationToken);
            return new SshConnectionWorkflowResult(
                savedBlocked,
                new SshConnectionTestResult(
                    SshConnectionTestOutcome.HostKeyRejected,
                    "确认后再次探测到不同指纹，已在读取密码前阻止登录。"));
        }

        var verified = coordinator.RecordMatchingObservation(pinned, DateTimeOffset.UtcNow);
        var savedVerified = await repository.SaveSshHostKeyTrustAsync(
            device.Id, verified, savedPinned.Revision, cancellationToken);
        var profile = CreateProfile(device, verified);
        using (var loginCandidate = CreatePlinkCandidate())
        {
            var login = await tester.TestLoginWithoutCommandAsync(
                loginCandidate, profile, cancellationToken);
            return new SshConnectionWorkflowResult(savedVerified, login);
        }
    }

    private static ConnectionProfile CreateProfile(DeviceRecord device, HostKeyTrust verified)
    {
        return new ConnectionProfile(
            device.DisplayName,
            device.Host,
            device.Port,
            ConnectionProtocol.Ssh,
            new SshConnectionOptions(
                verified.Endpoint,
                device.UserName,
                device.AuthenticationMethod,
                device.CredentialReference,
                device.PrivateKeyReference,
                verified));
    }

    private ComponentExecutionCandidate CreatePlinkCandidate()
    {
        var status = componentInspector.Inspect(TrustedComponentCatalog.Plink);
        if (!status.Available)
        {
            throw new InvalidOperationException(status.UserImpact + " " + status.OfflineInstructions);
        }

        return componentInspector.RevalidateForExecution(TrustedComponentCatalog.Plink, status);
    }

    private static void ValidateDevice(DeviceRecord device)
    {
        if (device == null)
        {
            throw new ArgumentNullException(nameof(device));
        }

        if (device.Protocol != ConnectionProtocol.Ssh)
        {
            throw new NotSupportedException("当前安全连接测试仅支持 SSH 设备。");
        }
    }
}
