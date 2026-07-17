using System;
using System.Collections.Generic;
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

    [Fact]
    public async Task Late_trust_result_from_previous_device_cannot_replace_current_device_state()
    {
        var first = Device("first.example.test");
        var second = Device("second.example.test");
        var service = new DeferredTrustWorkflowService();
        var viewModel = new DeviceConnectionViewModel(service);

        var selectingFirst = viewModel.SelectDeviceAsync(first);
        await service.WaitUntilRequestedAsync(first.Id);
        var selectingSecond = viewModel.SelectDeviceAsync(second);
        await service.WaitUntilRequestedAsync(second.Id);
        service.Complete(second, HostKeyTrust.Unconfigured(new SshEndpointIdentity(second.Host, second.Port)));
        await selectingSecond;
        service.Complete(first, HostKeyTrust.Unconfigured(new SshEndpointIdentity(first.Host, first.Port)));
        await selectingFirst;

        Assert.Same(second, viewModel.Device);
        Assert.Equal(DeviceConnectionViewModelState.ReadyToProbe, viewModel.State);
        Assert.Equal(string.Empty, viewModel.Fingerprint);
        Assert.True(viewModel.CanProbe);
    }

    [Fact]
    public async Task Trust_record_for_another_device_is_rejected_without_showing_its_fingerprint()
    {
        var selected = Device("selected.example.test");
        var other = Device("other.example.test");
        var trust = HostKeyTrust.Unconfigured(new SshEndpointIdentity(selected.Host, selected.Port));
        var service = new MismatchedTrustWorkflowService(
            new SshHostKeyTrustRecord(other.Id, trust, 0));
        var viewModel = new DeviceConnectionViewModel(service);

        await viewModel.SelectDeviceAsync(selected);

        Assert.Equal(DeviceConnectionViewModelState.Failed, viewModel.State);
        Assert.Equal(nameof(InvalidOperationException), viewModel.TechnicalDetails);
        Assert.Equal(string.Empty, viewModel.Fingerprint);
    }

    private static DeviceRecord Device(string host = "router.example.test")
    {
        return new DeviceRecord(
            DeviceId.New(),
            ProjectId.New(),
            "核心交换机",
            host,
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

    private sealed class DeferredTrustWorkflowService : ISshConnectionWorkflowService
    {
        private readonly Dictionary<DeviceId, TaskCompletionSource<bool>> requested =
            new Dictionary<DeviceId, TaskCompletionSource<bool>>();
        private readonly Dictionary<DeviceId, TaskCompletionSource<SshHostKeyTrustRecord>> results =
            new Dictionary<DeviceId, TaskCompletionSource<SshHostKeyTrustRecord>>();

        public Task<SshHostKeyTrustRecord> GetTrustAsync(
            DeviceRecord device,
            CancellationToken cancellationToken = default)
        {
            GetRequested(device.Id).TrySetResult(true);
            return GetResult(device.Id).Task;
        }

        public async Task WaitUntilRequestedAsync(DeviceId deviceId)
        {
            var task = GetRequested(deviceId).Task;
            var completed = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(task, completed);
            await task;
        }

        public void Complete(DeviceRecord device, HostKeyTrust trust)
        {
            GetResult(device.Id).TrySetResult(new SshHostKeyTrustRecord(device.Id, trust, 0));
        }

        public Task<SshConnectionWorkflowResult> ProbeAsync(
            DeviceRecord device,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<SshConnectionWorkflowResult> ConfirmAndTestAsync(
            DeviceRecord device,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        private TaskCompletionSource<bool> GetRequested(DeviceId deviceId)
        {
            if (!requested.TryGetValue(deviceId, out var value))
            {
                value = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                requested.Add(deviceId, value);
            }

            return value;
        }

        private TaskCompletionSource<SshHostKeyTrustRecord> GetResult(DeviceId deviceId)
        {
            if (!results.TryGetValue(deviceId, out var value))
            {
                value = new TaskCompletionSource<SshHostKeyTrustRecord>(TaskCreationOptions.RunContinuationsAsynchronously);
                results.Add(deviceId, value);
            }

            return value;
        }
    }

    private sealed class MismatchedTrustWorkflowService : ISshConnectionWorkflowService
    {
        private readonly SshHostKeyTrustRecord record;

        public MismatchedTrustWorkflowService(SshHostKeyTrustRecord record)
        {
            this.record = record;
        }

        public Task<SshHostKeyTrustRecord> GetTrustAsync(
            DeviceRecord device,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(record);
        }

        public Task<SshConnectionWorkflowResult> ProbeAsync(
            DeviceRecord device,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<SshConnectionWorkflowResult> ConfirmAndTestAsync(
            DeviceRecord device,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}
