using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Execution;
using Xunit;

namespace AssessmentTool.Windows.Tests.ViewModels;

public sealed class MainViewModelTests
{
    [Fact]
    public async Task Header_names_follow_workspace_project_and_device_selection()
    {
        var project = new ProjectRecord(ProjectId.New(), "客户", "等保项目", @"C:\Evidence", DateTimeOffset.UtcNow);
        var device = new DeviceRecord(DeviceId.New(), project.Id, "核心交换机", "192.0.2.10", 22,
            CredentialReference.New(), DateTimeOffset.UtcNow);
        var service = new FakeWorkspaceService(device);
        var workspace = new ProjectWorkspaceViewModel(service);
        var collection = new CollectionViewModel(
            new FakeCollectionWorkflowService(),
            new FakeDatabaseConfirmationService());
        var componentCenter = new ComponentCenterViewModel(
            new ComponentCenterViewModelTests.FakeComponentStatusService(
                ComponentCenterViewModelTests.UnavailableStatus(
                    AssessmentTool.Windows.Components.ComponentFailure.Missing)));
        await componentCenter.RefreshAsync();
        var viewModel = new MainViewModel(workspace, collection, componentCenter, () => { });
        var changes = new List<string>();
        viewModel.PropertyChanged += (_, args) => changes.Add(args.PropertyName ?? string.Empty);

        await workspace.SelectProjectAsync(project);
        workspace.SelectedDevice = device;

        Assert.Equal("等保项目", viewModel.CurrentProjectName);
        Assert.Equal("核心交换机", viewModel.CurrentDeviceName);
        Assert.Equal(1, viewModel.ProjectDeviceCount);
        Assert.Equal(1, viewModel.PendingConnectionTestCount);
        Assert.Equal(0, viewModel.CollectionFailureCount);
        Assert.Equal("只读模式已启用", viewModel.ReadOnlyProtectionStatus);
        Assert.Contains(nameof(MainViewModel.CurrentProjectName), changes);
        Assert.Contains(nameof(MainViewModel.CurrentDeviceName), changes);
        Assert.Contains(nameof(MainViewModel.ProjectDeviceCount), changes);
        Assert.Contains(nameof(MainViewModel.PendingConnectionTestCount), changes);
        Assert.Same(componentCenter, viewModel.ComponentCenter);
        Assert.False(viewModel.ComponentCenter.IsSshAvailable);
        var essentialNavigation = viewModel.NavigationItems.Where(item =>
            item.Title == "项目" || item.Title == "设备" || item.Title == "组件中心").ToArray();
        Assert.Equal(3, essentialNavigation.Length);
        Assert.All(essentialNavigation, item => Assert.True(item.IsAvailable));
    }

    [Fact]
    public async Task Dashboard_failure_count_tracks_collection_state()
    {
        var collection = new CollectionViewModel(
            new ThrowingCollectionWorkflowService(),
            new FakeDatabaseConfirmationService());
        var componentCenter = new ComponentCenterViewModel(
            new ComponentCenterViewModelTests.FakeComponentStatusService(
                ComponentCenterViewModelTests.AvailableStatus()));
        await componentCenter.RefreshAsync();
        var viewModel = new MainViewModel(collection, componentCenter, () => { });
        var project = new ProjectRecord(ProjectId.New(), "客户", "项目", @"C:\Evidence", DateTimeOffset.UtcNow);
        var device = new DeviceRecord(DeviceId.New(), project.Id, "设备", "192.0.2.2", 22,
            CredentialReference.New(), DateTimeOffset.UtcNow);
        collection.SelectProject(project);
        collection.SelectDevice(new CollectionDeviceSelection(device, true, CreateVerifiedHostKeyTrust(device)));

        await collection.StartAsync();

        Assert.Equal(1, viewModel.CollectionFailureCount);
    }

    [Fact]
    public async Task Ssh_component_refresh_only_gates_collection_start()
    {
        var project = new ProjectRecord(ProjectId.New(), "客户", "等保项目", @"C:\Evidence", DateTimeOffset.UtcNow);
        var device = new DeviceRecord(DeviceId.New(), project.Id, "核心交换机", "192.0.2.10", 22,
            CredentialReference.New(), DateTimeOffset.UtcNow);
        var collection = new CollectionViewModel(
            new FakeCollectionWorkflowService(),
            new FakeDatabaseConfirmationService());
        collection.SelectProject(project);
        collection.SelectDevice(new CollectionDeviceSelection(device, true, CreateVerifiedHostKeyTrust(device)));
        var componentCenter = new ComponentCenterViewModel(
            new ComponentCenterViewModelTests.FakeComponentStatusService(
                ComponentCenterViewModelTests.UnavailableStatus(
                    AssessmentTool.Windows.Components.ComponentFailure.Missing),
                ComponentCenterViewModelTests.AvailableStatus(),
                ComponentCenterViewModelTests.UnavailableStatus(
                    AssessmentTool.Windows.Components.ComponentFailure.Missing)));
        await componentCenter.RefreshAsync();

        var viewModel = new MainViewModel(collection, componentCenter, () => { });

        Assert.False(collection.StartCommand.CanExecute(null));
        AssertNavigationRemainsAvailable(viewModel);

        await componentCenter.RefreshAsync();

        Assert.True(collection.StartCommand.CanExecute(null));
        AssertNavigationRemainsAvailable(viewModel);

        await componentCenter.RefreshAsync();

        Assert.False(collection.StartCommand.CanExecute(null));
        AssertNavigationRemainsAvailable(viewModel);
    }

    [Fact]
    public async Task Confirmed_database_refreshes_visible_audit_history()
    {
        var project = new ProjectRecord(
            ProjectId.New(), "客户", "项目", @"C:\Evidence", DateTimeOffset.UtcNow);
        var device = new DeviceRecord(
            DeviceId.New(), project.Id, "Linux服务器", "192.0.2.20", 22,
            CredentialReference.New(), DateTimeOffset.UtcNow);
        var candidate = CreateDatabaseCandidate();
        var collection = new CollectionViewModel(
            new DatabaseCandidateWorkflowService(candidate),
            new FakeDatabaseConfirmationService());
        collection.SelectProject(project);
        collection.SelectDevice(new CollectionDeviceSelection(
            device, true, CreateVerifiedHostKeyTrust(device)));
        var componentCenter = new ComponentCenterViewModel(
            new ComponentCenterViewModelTests.FakeComponentStatusService(
                ComponentCenterViewModelTests.AvailableStatus()));
        await componentCenter.RefreshAsync();
        var evidenceService = new CountingEvidenceCenterService();
        var evidenceCenter = new EvidenceCenterViewModel(evidenceService);
        await evidenceCenter.SelectProjectAsync(project);
        var viewModel = new MainViewModel(
            null,
            collection,
            componentCenter,
            new DeviceConnectionViewModel(null),
            () => { },
            evidenceCenter);

        await collection.StartAsync();
        await collection.ConfirmDatabaseAsync(Assert.Single(collection.DatabaseCandidates));
        await WaitUntilAsync(() => evidenceService.LoadCount >= 2);

        Assert.Equal(CollectionViewModelState.DatabaseConfirmed, collection.State);
        Assert.Equal(2, evidenceService.LoadCount);
        Assert.Same(evidenceCenter, viewModel.EvidenceCenter);
    }

    private static DatabaseInstanceCandidate CreateDatabaseCandidate()
    {
        var timestamp = DateTimeOffset.UtcNow;
        var output = new CommandOutput(
            "database-host-discovery-linux-processes",
            "100 postgres-16",
            string.Empty,
            0,
            RemoteExecutionOutcome.Succeeded,
            null,
            timestamp,
            timestamp.AddSeconds(1));
        return Assert.Single(new HostDatabaseDiscovery().Detect(new[] { output }));
    }

    private static async Task WaitUntilAsync(Func<bool> predicate)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
        while (!predicate())
        {
            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException("等待证据中心自动刷新超时。");
            }

            await Task.Delay(20);
        }
    }

    private static HostKeyTrust CreateVerifiedHostKeyTrust(DeviceRecord device)
    {
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var observedAt = DateTimeOffset.UtcNow;
        var probing = coordinator.BeginProbe(
            HostKeyTrust.Unconfigured(new SshEndpointIdentity(device.Host, device.Port)));
        var awaiting = coordinator.RecordObservation(
            probing,
            "ssh-ed25519",
            "ssh-ed25519 255 SHA256:fixture",
            observedAt);
        var pinned = coordinator.Confirm(awaiting, observedAt.AddSeconds(1), "测试固定指纹");
        return coordinator.RecordMatchingObservation(pinned, observedAt.AddSeconds(2));
    }

    private static void AssertNavigationRemainsAvailable(MainViewModel viewModel)
    {
        var essentialNavigation = viewModel.NavigationItems.Where(item =>
            item.Title == "项目" || item.Title == "设备" || item.Title == "组件中心").ToArray();
        Assert.Equal(3, essentialNavigation.Length);
        Assert.All(essentialNavigation, item => Assert.True(item.IsAvailable));
    }

    private sealed class FakeWorkspaceService : IProjectWorkspaceService
    {
        private readonly DeviceRecord device;

        public FakeWorkspaceService(DeviceRecord device)
        {
            this.device = device;
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ProjectRecord>>(Array.Empty<ProjectRecord>());
        public Task<ProjectId> CreateProjectAsync(string customerName, string projectName, string evidenceRoot,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(ProjectId projectId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<DeviceRecord>>(new[] { device });
        public Task<DeviceId> AddDeviceAsync(ProjectId projectId, string displayName, string host, int port,
            char[] password, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DeviceId> AddSshDeviceAsync(ProjectId projectId, string displayName, string host, int port,
            string userName, TargetCategory category, char[] password,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DeviceId> AddSshPrivateKeyDeviceAsync(ProjectId projectId, string displayName, string host,
            int port, string userName, TargetCategory category, char[] privateKeyMaterial,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private sealed class FakeCollectionWorkflowService : ICollectionWorkflowService
    {
        public Task<CollectionWorkflowResult> RunAsync(
            CollectionWorkflowRequest request,
            IProgress<AssessmentTool.Core.Execution.CollectionProgress> progress,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(CollectionWorkflowResult.Stopped());
        }
    }

    private sealed class ThrowingCollectionWorkflowService : ICollectionWorkflowService
    {
        public Task<CollectionWorkflowResult> RunAsync(
            CollectionWorkflowRequest request,
            IProgress<AssessmentTool.Core.Execution.CollectionProgress> progress,
            CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("fixture");
        }
    }

    private sealed class FakeDatabaseConfirmationService : IDatabaseConfirmationService
    {
        public Task<DatabaseConfirmationRecord> ConfirmAsync(
            ProjectRecord project,
            DeviceRecord device,
            DatabaseInstanceCandidate candidate,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new DatabaseConfirmationRecord(
                project.Id,
                device.Id,
                candidate.Product,
                candidate.Version,
                candidate.InstallationType,
                candidate.InstanceName,
                candidate.PortEvidence,
                candidate.Evidence,
                candidate.Confidence,
                DateTimeOffset.UtcNow,
                "测试人工确认"));
        }
    }

    private sealed class DatabaseCandidateWorkflowService : ICollectionWorkflowService
    {
        private readonly DatabaseInstanceCandidate candidate;

        public DatabaseCandidateWorkflowService(DatabaseInstanceCandidate candidate)
        {
            this.candidate = candidate.RequireConfirmation();
        }

        public Task<CollectionWorkflowResult> RunAsync(
            CollectionWorkflowRequest request,
            IProgress<CollectionProgress> progress,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                CollectionWorkflowResult.RequiresDatabaseConfirmation(new[] { candidate }));
        }
    }

    private sealed class CountingEvidenceCenterService : IEvidenceCenterService
    {
        public int LoadCount { get; private set; }

        public Task<EvidenceCenterSnapshot> LoadAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            LoadCount++;
            return Task.FromResult(new EvidenceCenterSnapshot(
                projectId,
                Array.Empty<EvidenceCenterItem>()));
        }

        public Task<EvidenceCenterSnapshot> VerifyAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            return LoadAsync(projectId, cancellationToken);
        }
    }
}
