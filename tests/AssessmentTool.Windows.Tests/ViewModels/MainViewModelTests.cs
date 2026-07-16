using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Domain;
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
        var collection = new CollectionViewModel(new FakeCollectionWorkflowService());
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
        Assert.Contains(nameof(MainViewModel.CurrentProjectName), changes);
        Assert.Contains(nameof(MainViewModel.CurrentDeviceName), changes);
        Assert.Same(componentCenter, viewModel.ComponentCenter);
        Assert.False(viewModel.ComponentCenter.IsSshAvailable);
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
}
