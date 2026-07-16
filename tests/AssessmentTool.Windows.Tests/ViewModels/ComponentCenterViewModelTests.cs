using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Windows.Components;
using Xunit;

namespace AssessmentTool.Windows.Tests.ViewModels;

public sealed class ComponentCenterViewModelTests
{
    [Fact]
    public void Initial_state_does_not_start_detection_and_keeps_ssh_disabled()
    {
        var service = new FakeComponentStatusService();

        var viewModel = new ComponentCenterViewModel(service);

        Assert.Equal(ComponentCenterState.NotChecked, viewModel.State);
        Assert.Equal(ComponentItemState.Missing, viewModel.ComponentState);
        Assert.False(viewModel.IsSshAvailable);
        Assert.Equal(0, service.CallCount);
        Assert.Equal("Plink 连接组件", viewModel.ComponentName);
        Assert.Contains("不会自动下载、安装或替换组件", viewModel.AutomaticActionNotice);
    }

    [Fact]
    public async Task Trusted_component_becomes_available()
    {
        var service = new FakeComponentStatusService(AvailableStatus());
        var viewModel = new ComponentCenterViewModel(service);

        await viewModel.RefreshAsync();

        Assert.Equal(ComponentCenterState.Ready, viewModel.State);
        Assert.Equal(ComponentItemState.Available, viewModel.ComponentState);
        Assert.True(viewModel.IsSshAvailable);
        Assert.Contains("可用", viewModel.StatusText);
    }

    [Fact]
    public async Task Refresh_command_starts_the_same_refresh_flow()
    {
        var pendingResult = new TaskCompletionSource<ComponentStatus>();
        var service = new FakeComponentStatusService(pendingResult.Task);
        var viewModel = new ComponentCenterViewModel(service);

        viewModel.RefreshCommand.Execute(null);

        Assert.Equal(ComponentCenterState.Refreshing, viewModel.State);
        Assert.Equal(1, service.CallCount);
        pendingResult.SetResult(AvailableStatus());
        await Task.Yield();
        Assert.True(viewModel.IsSshAvailable);
    }

    [Fact]
    public async Task Missing_component_is_ready_but_only_disables_ssh()
    {
        var status = UnavailableStatus(ComponentFailure.Missing);
        var viewModel = new ComponentCenterViewModel(new FakeComponentStatusService(status));

        await viewModel.RefreshAsync();

        Assert.Equal(ComponentCenterState.Ready, viewModel.State);
        Assert.Equal(ComponentItemState.Missing, viewModel.ComponentState);
        Assert.False(viewModel.IsSshAvailable);
        Assert.Equal(status.UserImpact, viewModel.UserImpact);
        Assert.Equal(status.OfflineInstructions, viewModel.OfflineInstructions);
    }

    [Theory]
    [InlineData(ComponentFailure.InvalidTrustedPath)]
    [InlineData(ComponentFailure.UnsafeFileIdentity)]
    [InlineData(ComponentFailure.HashMismatch)]
    [InlineData(ComponentFailure.InvalidHash)]
    [InlineData(ComponentFailure.VersionTooLow)]
    [InlineData(ComponentFailure.InvalidVersion)]
    [InlineData(ComponentFailure.ArchitectureMismatch)]
    [InlineData(ComponentFailure.FileChangedDuringInspection)]
    public async Task Damaged_or_untrusted_component_maps_to_invalid(ComponentFailure failure)
    {
        var viewModel = new ComponentCenterViewModel(
            new FakeComponentStatusService(UnavailableStatus(failure)));

        await viewModel.RefreshAsync();

        Assert.Equal(ComponentCenterState.Ready, viewModel.State);
        Assert.Equal(ComponentItemState.Invalid, viewModel.ComponentState);
        Assert.False(viewModel.IsSshAvailable);
    }

    [Fact]
    public async Task Inspection_failure_maps_to_check_failed()
    {
        var viewModel = new ComponentCenterViewModel(
            new FakeComponentStatusService(UnavailableStatus(ComponentFailure.InspectionFailed)));

        await viewModel.RefreshAsync();

        Assert.Equal(ComponentCenterState.Ready, viewModel.State);
        Assert.Equal(ComponentItemState.CheckFailed, viewModel.ComponentState);
        Assert.False(viewModel.IsSshAvailable);
    }

    [Fact]
    public async Task Concurrent_refresh_is_single_flight_preserves_result_and_can_recover()
    {
        var pendingResult = new TaskCompletionSource<ComponentStatus>();
        var service = new FakeComponentStatusService(
            Task.FromResult(AvailableStatus()),
            pendingResult.Task,
            Task.FromResult(AvailableStatus()));
        var viewModel = new ComponentCenterViewModel(service);
        await viewModel.RefreshAsync();

        var firstRefresh = viewModel.RefreshAsync();
        var secondRefresh = viewModel.RefreshAsync();

        Assert.Same(firstRefresh, secondRefresh);
        Assert.Equal(ComponentCenterState.Refreshing, viewModel.State);
        Assert.Equal(ComponentItemState.Available, viewModel.ComponentState);
        Assert.True(viewModel.IsSshAvailable);
        Assert.Equal(2, service.CallCount);
        pendingResult.SetResult(UnavailableStatus(ComponentFailure.Missing));
        await firstRefresh;
        Assert.Equal(ComponentItemState.Missing, viewModel.ComponentState);

        await viewModel.RefreshAsync();

        Assert.Equal(3, service.CallCount);
        Assert.Equal(ComponentItemState.Available, viewModel.ComponentState);
        Assert.True(viewModel.IsSshAvailable);
    }

    [Fact]
    public async Task Service_exception_is_contained_and_center_can_retry()
    {
        var service = new FakeComponentStatusService(
            Task.FromException<ComponentStatus>(new InvalidOperationException("secret path")),
            AvailableStatus());
        var viewModel = new ComponentCenterViewModel(service);

        await viewModel.RefreshAsync();

        Assert.Equal(ComponentCenterState.Failed, viewModel.State);
        Assert.Equal(ComponentItemState.CheckFailed, viewModel.ComponentState);
        Assert.False(viewModel.IsSshAvailable);
        Assert.DoesNotContain("secret path", viewModel.StatusText);

        await viewModel.RefreshAsync();
        Assert.Equal(ComponentCenterState.Ready, viewModel.State);
        Assert.True(viewModel.IsSshAvailable);
    }

    [Fact]
    public void Production_service_only_exposes_fixed_component_construction()
    {
        var publicConstructors = typeof(ComponentStatusService)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance);

        Assert.Single(publicConstructors);
        Assert.Empty(publicConstructors[0].GetParameters());
        Assert.Single(typeof(IComponentStatusService).GetMethods());
        Assert.Equal(nameof(IComponentStatusService.GetPlinkStatusAsync),
            typeof(IComponentStatusService).GetMethods().Single().Name);
    }

    internal static ComponentStatus AvailableStatus()
    {
        var definition = TrustedComponentCatalog.Plink;
        var identity = new ComponentFileIdentity(
            @"C:\AssessmentTool\依赖组件\plink.exe",
            definition.ExpectedSha256,
            1024,
            DateTime.UtcNow,
            1,
            1,
            1);
        return new ComponentStatus(
            true,
            ComponentFailure.None,
            definition.Id,
            definition.AffectedFeature,
            "SSH连接组件可用。",
            "无需处理。",
            identity,
            definition.DefinitionKey);
    }

    internal static ComponentStatus UnavailableStatus(ComponentFailure failure)
    {
        var definition = TrustedComponentCatalog.Plink;
        return new ComponentStatus(
            false,
            failure,
            definition.Id,
            definition.AffectedFeature,
            "SSH连接暂不可用。",
            "请使用可信离线组件后重新检测。",
            null,
            definition.DefinitionKey);
    }

    internal sealed class FakeComponentStatusService : IComponentStatusService
    {
        private readonly Queue<Task<ComponentStatus>> results;

        internal FakeComponentStatusService()
            : this(Array.Empty<Task<ComponentStatus>>())
        {
        }

        internal FakeComponentStatusService(params ComponentStatus[] results)
            : this(results.Select(Task.FromResult).ToArray())
        {
        }

        internal FakeComponentStatusService(params Task<ComponentStatus>[] results)
        {
            this.results = new Queue<Task<ComponentStatus>>(results);
        }

        public int CallCount { get; private set; }

        public Task<ComponentStatus> GetPlinkStatusAsync()
        {
            CallCount++;
            if (results.Count == 0)
            {
                throw new InvalidOperationException("测试未配置检测结果。");
            }

            return results.Dequeue();
        }
    }
}
