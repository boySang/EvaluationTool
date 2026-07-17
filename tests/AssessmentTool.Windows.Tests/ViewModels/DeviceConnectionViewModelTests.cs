using System;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Sessions;
using Xunit;

namespace AssessmentTool.Windows.Tests.ViewModels;

public sealed class DeviceConnectionViewModelTests
{
    [Fact]
    public async Task Workflow_requires_probe_then_confirmation_before_reporting_login_success()
    {
        var device = Device();
        var endpoint = new SshEndpointIdentity(device.Host, device.Port);
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var observedAt = new DateTimeOffset(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
        var unconfigured = new SshHostKeyTrustRecord(
            device.Id, HostKeyTrust.Unconfigured(endpoint), 0);
        var awaiting = coordinator.RecordObservation(
            coordinator.BeginProbe(unconfigured.Trust),
            "ssh-ed25519",
            "ssh-ed25519 255 SHA256:fixture",
            observedAt);
        var pinned = coordinator.Confirm(awaiting, observedAt.AddMinutes(1), "人工确认");
        var verified = coordinator.RecordMatchingObservation(pinned, observedAt.AddMinutes(2));
        var service = new FakeWorkflowService(
            unconfigured,
            new SshConnectionWorkflowResult(
                new SshHostKeyTrustRecord(device.Id, awaiting, 1),
                new SshConnectionTestResult(
                    SshConnectionTestOutcome.FingerprintFound,
                    "待确认",
                    awaiting.ObservedAlgorithm,
                    awaiting.ObservedFingerprint)),
            new SshConnectionWorkflowResult(
                new SshHostKeyTrustRecord(device.Id, verified, 3),
                new SshConnectionTestResult(SshConnectionTestOutcome.Succeeded, "登录成功")));
        var viewModel = new DeviceConnectionViewModel(service);

        await viewModel.SelectDeviceAsync(device);
        Assert.True(viewModel.CanProbe);
        Assert.False(viewModel.CanConfirm);

        await viewModel.ProbeAsync();
        Assert.Equal(DeviceConnectionViewModelState.AwaitingConfirmation, viewModel.State);
        Assert.True(viewModel.CanConfirm);
        Assert.Equal(awaiting.ObservedFingerprint, viewModel.Fingerprint);

        await viewModel.ConfirmAndTestAsync();
        Assert.Equal(DeviceConnectionViewModelState.Succeeded, viewModel.State);
        Assert.False(viewModel.CanConfirm);
        Assert.Equal(1, service.ProbeCount);
        Assert.Equal(1, service.ConfirmCount);
    }

    private static DeviceRecord Device()
    {
        return new DeviceRecord(
            DeviceId.New(),
            ProjectId.New(),
            "核心交换机",
            "router.example.test",
            22,
            "audit-user",
            TargetCategory.NetworkDevice,
            ConnectionProtocol.Ssh,
            CredentialReference.New(),
            DateTimeOffset.UtcNow);
    }

    private sealed class FakeWorkflowService : ISshConnectionWorkflowService
    {
        private readonly SshHostKeyTrustRecord initial;
        private readonly SshConnectionWorkflowResult probe;
        private readonly SshConnectionWorkflowResult confirm;

        internal FakeWorkflowService(
            SshHostKeyTrustRecord initial,
            SshConnectionWorkflowResult probe,
            SshConnectionWorkflowResult confirm)
        {
            this.initial = initial;
            this.probe = probe;
            this.confirm = confirm;
        }

        internal int ProbeCount { get; private set; }
        internal int ConfirmCount { get; private set; }

        public Task<SshHostKeyTrustRecord> GetTrustAsync(
            DeviceRecord device,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(initial);
        }

        public Task<SshConnectionWorkflowResult> ProbeAsync(
            DeviceRecord device,
            CancellationToken cancellationToken = default)
        {
            ProbeCount++;
            return Task.FromResult(probe);
        }

        public Task<SshConnectionWorkflowResult> ConfirmAndTestAsync(
            DeviceRecord device,
            CancellationToken cancellationToken = default)
        {
            ConfirmCount++;
            return Task.FromResult(confirm);
        }
    }
}
