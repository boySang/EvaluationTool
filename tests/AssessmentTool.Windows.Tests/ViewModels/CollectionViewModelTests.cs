using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Execution;
using Xunit;

namespace AssessmentTool.Windows.Tests.ViewModels;

public sealed class CollectionViewModelTests
{
    [Fact]
    public void Start_is_disabled_until_project_device_component_and_host_key_are_ready()
    {
        var service = new FakeCollectionWorkflowService();
        var viewModel = new CollectionViewModel(service);
        var project = CreateProject();

        Assert.False(viewModel.StartCommand.CanExecute(null));

        viewModel.SelectProject(project);
        viewModel.SelectDevice(CreateSelection(project, componentAvailable: false, HostKeyTrustState.Verified));
        Assert.False(viewModel.StartCommand.CanExecute(null));
        Assert.True(viewModel.IsComponentCenterNavigationSuggested);

        viewModel.SelectDevice(CreateSelection(project, componentAvailable: true, HostKeyTrustState.AwaitingConfirmation));
        Assert.False(viewModel.StartCommand.CanExecute(null));

        viewModel.SelectDevice(CreateSelection(project, componentAvailable: true, HostKeyTrustState.Verified));
        Assert.True(viewModel.StartCommand.CanExecute(null));
    }

    [Fact]
    public void Required_component_override_controls_start_and_navigation_suggestion()
    {
        var service = new FakeCollectionWorkflowService();
        var project = CreateProject();
        var viewModel = new CollectionViewModel(service);
        viewModel.SelectProject(project);
        viewModel.SelectDevice(CreateSelection(project, componentAvailable: true, HostKeyTrustState.Verified));

        viewModel.SetRequiredComponentAvailability(false);

        Assert.False(viewModel.StartCommand.CanExecute(null));
        Assert.True(viewModel.IsComponentCenterNavigationSuggested);

        viewModel.SetRequiredComponentAvailability(true);

        Assert.True(viewModel.StartCommand.CanExecute(null));
        Assert.False(viewModel.IsComponentCenterNavigationSuggested);

        viewModel.SetRequiredComponentAvailability(false);

        Assert.False(viewModel.StartCommand.CanExecute(null));
        Assert.True(viewModel.IsComponentCenterNavigationSuggested);
        Assert.Empty(service.Requests);
    }

    [Fact]
    public void Clearing_device_or_switching_project_removes_previous_collection_readiness()
    {
        var service = new FakeCollectionWorkflowService();
        var firstProject = CreateProject();
        var secondProject = CreateProject();
        var viewModel = new CollectionViewModel(service);
        viewModel.SelectProject(firstProject);
        viewModel.SelectDevice(CreateSelection(firstProject, componentAvailable: true, HostKeyTrustState.Verified));
        Assert.True(viewModel.StartCommand.CanExecute(null));

        viewModel.ClearDeviceSelection();

        Assert.False(viewModel.StartCommand.CanExecute(null));

        viewModel.SelectDevice(CreateSelection(firstProject, componentAvailable: true, HostKeyTrustState.Verified));
        viewModel.SelectProject(secondProject);

        Assert.False(viewModel.StartCommand.CanExecute(null));
    }

    [Fact]
    public void Device_selection_rejects_host_key_trust_for_another_endpoint()
    {
        var project = CreateProject();
        var device = CreateDevice(project);
        var trust = CreateHostKeyTrust("another-device.example.test", 22, HostKeyTrustState.Verified);

        var error = Assert.Throws<ArgumentException>(() =>
            new CollectionDeviceSelection(device, true, trust));

        Assert.Equal("hostKeyTrust", error.ParamName);
    }

    [Fact]
    public async Task Ambiguous_detection_opens_confirmation_panel_instead_of_executing()
    {
        var candidate = CreateCandidate("A", 0.70);
        var service = new FakeCollectionWorkflowService(
            CollectionWorkflowResult.RequiresConfirmation(new[] { candidate }));
        var viewModel = CreateReadyViewModel(service);

        await viewModel.StartAsync();

        Assert.Equal(CollectionViewModelState.AwaitingConfirmation, viewModel.State);
        Assert.True(viewModel.IsDetectionConfirmationVisible);
        Assert.Single(viewModel.DetectionCandidates);
        Assert.Empty(viewModel.CompletedCommands);
        Assert.Single(service.Requests);
        Assert.Null(service.Requests[0].ConfirmedCandidate);
        Assert.False(viewModel.StartCommand.CanExecute(null));
    }

    [Fact]
    public async Task Progress_updates_public_collection_status()
    {
        var service = new FakeCollectionWorkflowService(
            new[] { CreateProgress(CollectionState.Executing, "正在执行只读命令", "cmd-2", 1, 3) },
            CollectionWorkflowResult.Completed(new[] { new CompletedCollectionCommand("cmd-2") }));
        var viewModel = CreateReadyViewModel(service);

        await viewModel.StartAsync();

        Assert.Equal(CollectionState.Executing, viewModel.ProgressState);
        Assert.Equal("正在执行只读命令", viewModel.ProgressMessage);
        Assert.Equal("cmd-2", viewModel.CurrentCommand);
        Assert.Equal(1, viewModel.CompletedCommandCount);
        Assert.Equal(3, viewModel.TotalCommandCount);
    }

    [Fact]
    public async Task Confirming_detection_retries_with_selected_candidate()
    {
        var candidate = CreateCandidate("A", 0.70);
        var service = new FakeCollectionWorkflowService(
            CollectionWorkflowResult.RequiresConfirmation(new[] { candidate }),
            CollectionWorkflowResult.Completed(new[] { new CompletedCollectionCommand("cmd-1") }));
        var viewModel = CreateReadyViewModel(service);

        await viewModel.StartAsync();
        await viewModel.ConfirmAndRetryAsync(candidate);

        Assert.Equal(CollectionViewModelState.Completed, viewModel.State);
        Assert.False(viewModel.IsDetectionConfirmationVisible);
        Assert.Single(viewModel.CompletedCommands);
        Assert.Equal(2, service.Requests.Count);
        Assert.Same(candidate, service.Requests[1].ConfirmedCandidate);
    }

    [Fact]
    public async Task Database_candidates_require_confirmation_without_starting_database_collection()
    {
        var candidate = CreateDatabaseCandidate("PostgreSQL", string.Empty, "postgresql.service");
        var service = new FakeCollectionWorkflowService(
            CollectionWorkflowResult.RequiresDatabaseConfirmation(new[] { candidate }));
        var viewModel = CreateReadyViewModel(service);

        await viewModel.StartAsync();

        Assert.Equal(CollectionViewModelState.AwaitingDatabaseConfirmation, viewModel.State);
        Assert.True(viewModel.IsDatabaseConfirmationVisible);
        Assert.Same(candidate, Assert.Single(viewModel.DatabaseCandidates));
        Assert.False(viewModel.StartCommand.CanExecute(null));

        viewModel.ConfirmDatabase(candidate);

        Assert.Equal(CollectionViewModelState.DatabaseConfirmed, viewModel.State);
        Assert.False(viewModel.IsDatabaseConfirmationVisible);
        Assert.Same(candidate, viewModel.SelectedDatabaseCandidate);
        Assert.Single(service.Requests);
    }

    [Fact]
    public async Task Project_and_device_selection_are_frozen_while_collection_is_running()
    {
        var service = new BlockingCollectionWorkflowService();
        var viewModel = CreateReadyViewModel(service);
        var running = viewModel.StartAsync();
        await AwaitWithTimeout(service.Started.Task);

        Assert.Throws<InvalidOperationException>(() => viewModel.SelectProject(CreateProject()));
        Assert.Throws<InvalidOperationException>(() =>
            viewModel.SelectDevice(CreateSelection(CreateProject(), true, HostKeyTrustState.Verified)));
        Assert.Throws<InvalidOperationException>(() => viewModel.ClearDeviceSelection());

        viewModel.Stop();
        await AwaitWithTimeout(running);
    }

    [Fact]
    public async Task Database_confirmation_rejects_candidate_outside_current_results()
    {
        var candidate = CreateDatabaseCandidate("PostgreSQL", string.Empty, "postgresql.service");
        var other = CreateDatabaseCandidate("MySQL", string.Empty, "mysql.service");
        var service = new FakeCollectionWorkflowService(
            CollectionWorkflowResult.RequiresDatabaseConfirmation(new[] { candidate }));
        var viewModel = CreateReadyViewModel(service);
        await viewModel.StartAsync();

        var error = Assert.Throws<InvalidOperationException>(() => viewModel.ConfirmDatabase(other));

        Assert.Equal("只能确认当前数据库候选项。", error.Message);
        Assert.Null(viewModel.SelectedDatabaseCandidate);
        Assert.Equal(CollectionViewModelState.AwaitingDatabaseConfirmation, viewModel.State);
        Assert.Single(service.Requests);
    }

    [Fact]
    public async Task Stop_cancels_active_collection_and_enters_stopped_state()
    {
        var service = new BlockingCollectionWorkflowService();
        var viewModel = CreateReadyViewModel(service);
        var running = viewModel.StartAsync();
        await AwaitWithTimeout(service.Started.Task);

        viewModel.Stop();
        await AwaitWithTimeout(running);

        Assert.True(service.WasCancelled);
        Assert.Equal(CollectionViewModelState.Stopped, viewModel.State);
        Assert.False(viewModel.StopCommand.CanExecute(null));
    }

    [Fact]
    public async Task Stop_request_cannot_be_overwritten_by_a_late_completed_result()
    {
        var service = new CancellationIgnoringWorkflowService();
        var viewModel = CreateReadyViewModel(service);
        var running = viewModel.StartAsync();
        await AwaitWithTimeout(service.Started.Task);

        viewModel.Stop();
        service.Complete();
        await AwaitWithTimeout(running);

        Assert.Equal(CollectionViewModelState.Stopped, viewModel.State);
        Assert.Empty(viewModel.CompletedCommands);
    }

    [Fact]
    public async Task Exception_after_stop_request_still_ends_as_stopped()
    {
        var service = new CancellationThenFailureWorkflowService();
        var viewModel = CreateReadyViewModel(service);
        var running = viewModel.StartAsync();
        await AwaitWithTimeout(service.Started.Task);

        viewModel.Stop();
        service.Fail();
        await AwaitWithTimeout(running);

        Assert.Equal(CollectionViewModelState.Stopped, viewModel.State);
        Assert.Null(viewModel.Error);
    }

    [Fact]
    public async Task Failure_exposes_four_part_structured_error()
    {
        var error = new CollectionError(
            "连接失败",
            "组件不可用或网络中断",
            "检查组件中心和设备连接后重试",
            "ConnectionException: redacted");
        var service = new FakeCollectionWorkflowService(CollectionWorkflowResult.Failed(error));
        var viewModel = CreateReadyViewModel(service);

        await viewModel.StartAsync();

        Assert.Equal(CollectionViewModelState.Failed, viewModel.State);
        Assert.NotNull(viewModel.Error);
        Assert.Equal("连接失败", viewModel.Error!.Summary);
        Assert.Equal("组件不可用或网络中断", viewModel.Error.PossibleCause);
        Assert.Equal("检查组件中心和设备连接后重试", viewModel.Error.RecommendedAction);
        Assert.Equal("ConnectionException: redacted", viewModel.Error.TechnicalDetails);
    }

    [Fact]
    public async Task Service_errors_are_redacted_across_all_four_fields()
    {
        var error = new CollectionError(
            "连接失败 password=summary-secret",
            "token=cause-secret",
            "pwd=action-secret",
            "secret=technical-secret");
        var viewModel = CreateReadyViewModel(
            new FakeCollectionWorkflowService(CollectionWorkflowResult.Failed(error)));

        await viewModel.StartAsync();

        var combined = string.Join("|", new[]
        {
            viewModel.Error!.Summary,
            viewModel.Error.PossibleCause,
            viewModel.Error.RecommendedAction,
            viewModel.Error.TechnicalDetails
        });
        Assert.DoesNotContain("summary-secret", combined);
        Assert.DoesNotContain("cause-secret", combined);
        Assert.DoesNotContain("action-secret", combined);
        Assert.DoesNotContain("technical-secret", combined);
        Assert.Contains("***", combined);
    }

    [Fact]
    public async Task Unexpected_failure_technical_details_only_expose_exception_type()
    {
        var service = new ThrowingCollectionWorkflowService(
            new InvalidOperationException("敏感远程输出和连接信息"));
        var viewModel = CreateReadyViewModel(service);

        await viewModel.StartAsync();

        Assert.Equal(CollectionViewModelState.Failed, viewModel.State);
        Assert.NotNull(viewModel.Error);
        Assert.Equal(nameof(InvalidOperationException), viewModel.Error!.TechnicalDetails);
        Assert.DoesNotContain("敏感远程输出和连接信息", viewModel.Error.TechnicalDetails);
    }

    [Fact]
    public void View_model_and_workflow_request_do_not_expose_arbitrary_command_text()
    {
        var publicProperties = typeof(CollectionViewModel).GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Concat(typeof(CollectionWorkflowRequest).GetProperties(BindingFlags.Instance | BindingFlags.Public));

        Assert.DoesNotContain(publicProperties, property =>
            property.Name.IndexOf("CommandText", StringComparison.OrdinalIgnoreCase) >= 0
            || property.Name.IndexOf("RemoteCommand", StringComparison.OrdinalIgnoreCase) >= 0);
    }

    private static CollectionViewModel CreateReadyViewModel(ICollectionWorkflowService service)
    {
        var project = CreateProject();
        var viewModel = new CollectionViewModel(service);
        viewModel.SelectProject(project);
        viewModel.SelectDevice(CreateSelection(project, componentAvailable: true, HostKeyTrustState.Verified));
        return viewModel;
    }

    private static ProjectRecord CreateProject()
    {
        return new ProjectRecord(ProjectId.New(), "客户", "项目", @"C:\Evidence", DateTimeOffset.UtcNow);
    }

    private static async Task AwaitWithTimeout(Task task)
    {
        var completed = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.Same(task, completed);
        await task;
    }

    private static CollectionDeviceSelection CreateSelection(
        ProjectRecord project,
        bool componentAvailable,
        HostKeyTrustState hostKeyTrustState)
    {
        var device = CreateDevice(project);
        var hostKeyTrust = CreateHostKeyTrust(device.Host, device.Port, hostKeyTrustState);
        return new CollectionDeviceSelection(device, componentAvailable, hostKeyTrust);
    }

    private static DeviceRecord CreateDevice(ProjectRecord project)
    {
        return new DeviceRecord(
            DeviceId.New(),
            project.Id,
            "设备",
            "192.0.2.10",
            22,
            CredentialReference.New(),
            DateTimeOffset.UtcNow);
    }

    private static HostKeyTrust CreateHostKeyTrust(
        string host,
        int port,
        HostKeyTrustState state)
    {
        var endpoint = new SshEndpointIdentity(host, port);
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var probing = coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint));
        var observedAt = DateTimeOffset.UtcNow;
        var awaiting = coordinator.RecordObservation(
            probing,
            "ssh-ed25519",
            "ssh-ed25519 255 SHA256:fixture",
            observedAt);

        if (state == HostKeyTrustState.AwaitingConfirmation)
        {
            return awaiting;
        }

        var pinned = coordinator.Confirm(awaiting, observedAt.AddSeconds(1), "测试固定指纹");
        return state == HostKeyTrustState.Verified
            ? coordinator.RecordMatchingObservation(pinned, observedAt.AddSeconds(2))
            : pinned;
    }

    private static DetectionCandidate CreateCandidate(string model, double confidence)
    {
        return new DetectionCandidate(
            TargetCategory.NetworkDevice,
            "Vendor",
            "Family",
            model,
            "1.0",
            "只读识别依据",
            confidence);
    }

    private static CollectionProgress CreateProgress(
        CollectionState state,
        string message,
        string? commandId,
        int completedCommands,
        int totalCommands)
    {
        return (CollectionProgress)Activator.CreateInstance(
            typeof(CollectionProgress),
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            args: new object?[] { state, message, commandId, completedCommands, totalCommands },
            culture: null)!;
    }

    private static DatabaseInstanceCandidate CreateDatabaseCandidate(
        string product,
        string version,
        string instanceName)
    {
        var processName = product == "PostgreSQL"
            ? string.IsNullOrWhiteSpace(version) ? "postgres" : "postgres-" + version
            : string.IsNullOrWhiteSpace(version) ? "mysqld" : "mysqld-" + version;
        var timestamp = DateTimeOffset.UtcNow;
        var output = new CommandOutput(
            "database-host-discovery-linux-processes",
            " 100 " + processName + " /fixture/" + instanceName,
            string.Empty,
            0,
            RemoteExecutionOutcome.Succeeded,
            null,
            timestamp,
            timestamp.AddSeconds(1));

        return Assert.Single(new HostDatabaseDiscovery().Detect(new[] { output }));
    }

    private sealed class FakeCollectionWorkflowService : ICollectionWorkflowService
    {
        private readonly Queue<CollectionWorkflowResult> results;
        private readonly IReadOnlyList<CollectionProgress> progressUpdates;

        public FakeCollectionWorkflowService(params CollectionWorkflowResult[] results)
            : this(Array.Empty<CollectionProgress>(), results)
        {
        }

        public FakeCollectionWorkflowService(
            IReadOnlyList<CollectionProgress> progressUpdates,
            params CollectionWorkflowResult[] results)
        {
            this.progressUpdates = progressUpdates;
            this.results = new Queue<CollectionWorkflowResult>(results.Length == 0
                ? new[] { CollectionWorkflowResult.Completed(Array.Empty<CompletedCollectionCommand>()) }
                : results);
        }

        public List<CollectionWorkflowRequest> Requests { get; } = new List<CollectionWorkflowRequest>();

        public Task<CollectionWorkflowResult> RunAsync(
            CollectionWorkflowRequest request,
            IProgress<CollectionProgress> progress,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            foreach (var update in progressUpdates)
            {
                progress.Report(update);
            }

            return Task.FromResult(results.Dequeue());
        }
    }

    private sealed class BlockingCollectionWorkflowService : ICollectionWorkflowService
    {
        public TaskCompletionSource<bool> Started { get; } =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool WasCancelled { get; private set; }

        public async Task<CollectionWorkflowResult> RunAsync(
            CollectionWorkflowRequest request,
            IProgress<CollectionProgress> progress,
            CancellationToken cancellationToken)
        {
            Started.SetResult(true);
            try
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
                throw new InvalidOperationException("不可达");
            }
            catch (OperationCanceledException)
            {
                WasCancelled = true;
                return CollectionWorkflowResult.Stopped();
            }
        }
    }

    private sealed class ThrowingCollectionWorkflowService : ICollectionWorkflowService
    {
        private readonly Exception exception;

        public ThrowingCollectionWorkflowService(Exception exception)
        {
            this.exception = exception;
        }

        public Task<CollectionWorkflowResult> RunAsync(
            CollectionWorkflowRequest request,
            IProgress<CollectionProgress> progress,
            CancellationToken cancellationToken)
        {
            throw exception;
        }
    }

    private sealed class CancellationIgnoringWorkflowService : ICollectionWorkflowService
    {
        private readonly TaskCompletionSource<CollectionWorkflowResult> completion =
            new TaskCompletionSource<CollectionWorkflowResult>(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<bool> Started { get; } =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<CollectionWorkflowResult> RunAsync(
            CollectionWorkflowRequest request,
            IProgress<CollectionProgress> progress,
            CancellationToken cancellationToken)
        {
            Started.SetResult(true);
            return completion.Task;
        }

        public void Complete()
        {
            completion.SetResult(CollectionWorkflowResult.Completed(
                new[] { new CompletedCollectionCommand("must-not-complete") }));
        }
    }

    private sealed class CancellationThenFailureWorkflowService : ICollectionWorkflowService
    {
        private readonly TaskCompletionSource<CollectionWorkflowResult> completion =
            new TaskCompletionSource<CollectionWorkflowResult>(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<bool> Started { get; } =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<CollectionWorkflowResult> RunAsync(
            CollectionWorkflowRequest request,
            IProgress<CollectionProgress> progress,
            CancellationToken cancellationToken)
        {
            Started.SetResult(true);
            return completion.Task;
        }

        public void Fail()
        {
            completion.SetException(new InvalidOperationException("取消后的底层关闭异常"));
        }
    }
}
