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
using AssessmentTool.Windows.Storage;
using Xunit;

namespace AssessmentTool.Windows.Tests.ViewModels;

public sealed class CollectionViewModelTests
{
    [Fact]
    public void Start_is_disabled_until_project_device_component_and_host_key_are_ready()
    {
        var service = new FakeCollectionWorkflowService();
        var viewModel = new CollectionViewModel(service, new FakeDatabaseConfirmationService());
        var project = CreateProject();

        Assert.False(viewModel.StartCommand.CanExecute(null));

        viewModel.SelectProject(project);
        viewModel.SelectDevice(CreateSelection(project, componentAvailable: false, HostKeyTrustState.Verified));
        Assert.False(viewModel.StartCommand.CanExecute(null));
        Assert.True(viewModel.IsComponentCenterNavigationSuggested);

        viewModel.SelectDevice(CreateSelection(project, componentAvailable: true, HostKeyTrustState.AwaitingConfirmation));
        Assert.False(viewModel.StartCommand.CanExecute(null));

        viewModel.SelectDevice(CreateSelection(project, componentAvailable: true, HostKeyTrustState.Verified));
        SelectGenericLinuxAdapter(viewModel);
        Assert.True(viewModel.StartCommand.CanExecute(null));
    }

    [Fact]
    public async Task Network_device_requires_explicit_adapter_selection_before_collection()
    {
        var service = new FakeCollectionWorkflowService();
        var project = CreateProject();
        var viewModel = new CollectionViewModel(service, new FakeDatabaseConfirmationService());
        viewModel.SelectProject(project);
        var device = CreateDevice(project, TargetCategory.NetworkDevice);
        viewModel.SelectDevice(new CollectionDeviceSelection(
            device,
            true,
            CreateHostKeyTrust(device.Host, device.Port, HostKeyTrustState.Verified)));

        Assert.True(viewModel.IsAdapterSelectionVisible);
        var option = Assert.Single(
            viewModel.AdapterOptions,
            item => item.Id == CollectionAdapterId.HuaweiVrp);
        Assert.Contains(viewModel.AdapterOptions, item => item.Id == CollectionAdapterId.H3cComware);
        Assert.Equal(CollectionAdapterId.HuaweiVrp, option.Id);
        Assert.Null(viewModel.SelectedAdapterOption);
        Assert.False(viewModel.StartCommand.CanExecute(null));

        viewModel.SelectedAdapterOption = option;
        await viewModel.StartAsync();

        Assert.Equal(CollectionAdapterId.HuaweiVrp, Assert.Single(service.Requests).AdapterId);
    }

    [Fact]
    public async Task Server_requires_explicit_linux_or_windows_adapter_selection_before_collection()
    {
        var service = new FakeCollectionWorkflowService();
        var project = CreateProject();
        var viewModel = new CollectionViewModel(service, new FakeDatabaseConfirmationService());
        viewModel.SelectProject(project);
        var device = CreateDevice(project, TargetCategory.Server);
        viewModel.SelectDevice(new CollectionDeviceSelection(
            device,
            true,
            CreateHostKeyTrust(device.Host, device.Port, HostKeyTrustState.Verified)));

        Assert.True(viewModel.IsAdapterSelectionVisible);
        Assert.Contains(viewModel.AdapterOptions, item => item.Id == CollectionAdapterId.GenericLinux);
        var windowsOption = Assert.Single(
            viewModel.AdapterOptions,
            item => item.Id == CollectionAdapterId.WindowsServerSsh);
        Assert.Null(viewModel.SelectedAdapterOption);
        Assert.False(viewModel.StartCommand.CanExecute(null));

        viewModel.SelectedAdapterOption = windowsOption;
        await viewModel.StartAsync();

        Assert.Equal(CollectionAdapterId.WindowsServerSsh, Assert.Single(service.Requests).AdapterId);
        Assert.Contains("域控制器", viewModel.AdapterScopeNotice);
    }

    [Fact]
    public void Switching_network_device_clears_previous_adapter_confirmation()
    {
        var project = CreateProject();
        var viewModel = new CollectionViewModel(
            new FakeCollectionWorkflowService(),
            new FakeDatabaseConfirmationService());
        viewModel.SelectProject(project);
        var firstDevice = CreateDevice(project, TargetCategory.NetworkDevice);
        viewModel.SelectDevice(new CollectionDeviceSelection(
            firstDevice,
            true,
            CreateHostKeyTrust(firstDevice.Host, firstDevice.Port, HostKeyTrustState.Verified)));
        viewModel.SelectedAdapterOption = Assert.Single(
            viewModel.AdapterOptions,
            item => item.Id == CollectionAdapterId.HuaweiVrp);

        var secondDevice = CreateDevice(project, TargetCategory.NetworkDevice);
        viewModel.SelectDevice(new CollectionDeviceSelection(
            secondDevice,
            true,
            CreateHostKeyTrust(secondDevice.Host, secondDevice.Port, HostKeyTrustState.Verified)));

        Assert.Null(viewModel.SelectedAdapterOption);
        Assert.False(viewModel.StartCommand.CanExecute(null));
    }

    [Fact]
    public void Required_component_override_controls_start_and_navigation_suggestion()
    {
        var service = new FakeCollectionWorkflowService();
        var project = CreateProject();
        var viewModel = new CollectionViewModel(service, new FakeDatabaseConfirmationService());
        viewModel.SelectProject(project);
        viewModel.SelectDevice(CreateSelection(project, componentAvailable: true, HostKeyTrustState.Verified));
        SelectGenericLinuxAdapter(viewModel);

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
        var viewModel = new CollectionViewModel(service, new FakeDatabaseConfirmationService());
        viewModel.SelectProject(firstProject);
        viewModel.SelectDevice(CreateSelection(firstProject, componentAvailable: true, HostKeyTrustState.Verified));
        SelectGenericLinuxAdapter(viewModel);
        Assert.True(viewModel.StartCommand.CanExecute(null));

        viewModel.ClearDeviceSelection();

        Assert.False(viewModel.StartCommand.CanExecute(null));

        viewModel.SelectDevice(CreateSelection(firstProject, componentAvailable: true, HostKeyTrustState.Verified));
        SelectGenericLinuxAdapter(viewModel);
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
            CollectionWorkflowResult.RequiresConfirmation(new[] { candidate }, Guid.NewGuid()));
        var confirmationService = new FakeDatabaseConfirmationService();
        var viewModel = CreateReadyViewModel(service, confirmationService);

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
        var pendingBatchId = Guid.NewGuid();
        var service = new FakeCollectionWorkflowService(
            CollectionWorkflowResult.RequiresConfirmation(new[] { candidate }, pendingBatchId),
            CollectionWorkflowResult.Completed(new[] { new CompletedCollectionCommand("cmd-1") }));
        var viewModel = CreateReadyViewModel(service);

        await viewModel.StartAsync();
        await viewModel.ConfirmAndRetryAsync(candidate);

        Assert.Equal(CollectionViewModelState.Completed, viewModel.State);
        Assert.False(viewModel.IsDetectionConfirmationVisible);
        Assert.Single(viewModel.CompletedCommands);
        Assert.Equal(2, service.Requests.Count);
        Assert.Same(candidate, service.Requests[1].ConfirmedCandidate);
        Assert.Equal(pendingBatchId, service.Requests[1].PendingIdentificationBatchId);
    }

    [Fact]
    public async Task Restored_detection_requires_current_trusted_device_and_is_revalidated_before_collection()
    {
        var project = CreateProject();
        var device = CreateDevice(project);
        var candidate = CreateCandidate("A", 0.70);
        var pending = new PendingDeviceIdentificationBatch(
            Guid.NewGuid(), device.Id, 1, new[] { candidate }, DateTimeOffset.UtcNow);
        var repository = new FakePendingIdentificationRepository(pending);
        var service = new FakeCollectionWorkflowService(
            CollectionWorkflowResult.Completed(new[] { new CompletedCollectionCommand("cmd-1") }));
        var viewModel = new CollectionViewModel(
            service,
            new FakeDatabaseConfirmationService(),
            repository);
        viewModel.SelectProject(project);

        await viewModel.RestorePendingIdentificationAsync(device);

        Assert.Equal(CollectionViewModelState.AwaitingConfirmation, viewModel.State);
        Assert.True(viewModel.IsRecoveredIdentification);
        Assert.False(viewModel.ConfirmDetectionCommand.CanExecute(candidate));
        Assert.Contains("重新执行低风险识别", viewModel.ProgressMessage);

        var trust = CreateHostKeyTrust(device.Host, device.Port, HostKeyTrustState.Verified);
        viewModel.SelectDevice(new CollectionDeviceSelection(device, true, trust));
        Assert.True(viewModel.ConfirmDetectionCommand.CanExecute(candidate));

        await viewModel.ConfirmAndRetryAsync(candidate);

        var request = Assert.Single(service.Requests);
        Assert.Same(candidate, request.ConfirmedCandidate);
        Assert.Equal(pending.BatchId, request.PendingIdentificationBatchId);
        Assert.Equal(CollectionViewModelState.Completed, viewModel.State);
        Assert.False(viewModel.IsRecoveredIdentification);
    }

    [Fact]
    public async Task Restored_windows_server_candidate_selects_windows_adapter_without_running_commands()
    {
        var project = CreateProject();
        var device = CreateDevice(project, TargetCategory.Server);
        var candidate = new DetectionCandidate(
            TargetCategory.Server,
            "Microsoft",
            "Windows Server",
            "Standard",
            "2022",
            "ProductName REG_SZ Windows Server 2022 Standard",
            0.89);
        var pending = new PendingDeviceIdentificationBatch(
            Guid.NewGuid(),
            device.Id,
            1,
            new[] { candidate },
            DateTimeOffset.UtcNow);
        var viewModel = new CollectionViewModel(
            new FakeCollectionWorkflowService(),
            new FakeDatabaseConfirmationService(),
            new FakePendingIdentificationRepository(pending));
        viewModel.SelectProject(project);

        await viewModel.RestorePendingIdentificationAsync(device);
        viewModel.SelectDevice(new CollectionDeviceSelection(
            device,
            true,
            CreateHostKeyTrust(device.Host, device.Port, HostKeyTrustState.Verified)));

        Assert.Equal(CollectionAdapterId.WindowsServerSsh, viewModel.SelectedAdapterOption!.Id);
        Assert.Equal(CollectionViewModelState.AwaitingConfirmation, viewModel.State);
        Assert.Contains("域控制器", viewModel.AdapterScopeNotice);
    }

    [Fact]
    public async Task Pending_identification_restore_blocks_collection_until_local_lookup_finishes()
    {
        var project = CreateProject();
        var device = CreateDevice(project);
        var repository = new BlockingPendingIdentificationRepository();
        var viewModel = new CollectionViewModel(
            new FakeCollectionWorkflowService(),
            new FakeDatabaseConfirmationService(),
            repository);
        viewModel.SelectProject(project);
        viewModel.SelectDevice(new CollectionDeviceSelection(
            device,
            true,
            CreateHostKeyTrust(device.Host, device.Port, HostKeyTrustState.Verified)));
        SelectGenericLinuxAdapter(viewModel);
        Assert.True(viewModel.StartCommand.CanExecute(null));

        var restoring = viewModel.RestorePendingIdentificationAsync(device);
        await AwaitWithTimeout(repository.Started.Task);

        Assert.Equal(CollectionViewModelState.RestoringIdentification, viewModel.State);
        Assert.False(viewModel.StartCommand.CanExecute(null));
        Assert.Contains("正在检查", viewModel.ProgressMessage);

        repository.Complete(null);
        await AwaitWithTimeout(restoring);

        Assert.Equal(CollectionViewModelState.Ready, viewModel.State);
        Assert.True(viewModel.StartCommand.CanExecute(null));
    }

    [Fact]
    public async Task Switching_devices_clears_previous_device_progress_candidates_and_results()
    {
        var project = CreateProject();
        var databaseCandidate = CreateDatabaseCandidate("PostgreSQL", string.Empty, "postgresql.service");
        var service = new FakeCollectionWorkflowService(
            new[] { CreateProgress(CollectionState.Executing, "旧设备采集中", "old-command", 2, 4) },
            CollectionWorkflowResult.RequiresDatabaseConfirmation(
                new[] { databaseCandidate },
                new[] { new CompletedCollectionCommand("old-command") }));
        var viewModel = new CollectionViewModel(service, new FakeDatabaseConfirmationService());
        viewModel.SelectProject(project);
        viewModel.SelectDevice(CreateSelection(project, true, HostKeyTrustState.Verified));
        SelectGenericLinuxAdapter(viewModel);
        await viewModel.StartAsync();
        Assert.NotEmpty(viewModel.DatabaseCandidates);
        Assert.NotEmpty(viewModel.CompletedCommands);

        viewModel.SelectDevice(CreateSelection(project, true, HostKeyTrustState.Verified));
        SelectGenericLinuxAdapter(viewModel);

        Assert.Equal(CollectionViewModelState.Ready, viewModel.State);
        Assert.Null(viewModel.ProgressState);
        Assert.Equal(string.Empty, viewModel.ProgressMessage);
        Assert.Null(viewModel.CurrentCommand);
        Assert.Equal(0, viewModel.CompletedCommandCount);
        Assert.Equal(0, viewModel.TotalCommandCount);
        Assert.Empty(viewModel.DatabaseCandidates);
        Assert.Empty(viewModel.CompletedCommands);
        Assert.Null(viewModel.Error);
    }

    [Fact]
    public async Task Database_candidates_require_confirmation_without_starting_database_collection()
    {
        var candidate = CreateDatabaseCandidate("PostgreSQL", string.Empty, "postgresql.service");
        var service = new FakeCollectionWorkflowService(
            CollectionWorkflowResult.RequiresDatabaseConfirmation(new[] { candidate }));
        var confirmationService = new FakeDatabaseConfirmationService();
        var viewModel = CreateReadyViewModel(service, confirmationService);

        await viewModel.StartAsync();

        Assert.Equal(CollectionViewModelState.AwaitingDatabaseConfirmation, viewModel.State);
        Assert.True(viewModel.IsDatabaseConfirmationVisible);
        Assert.Same(candidate, Assert.Single(viewModel.DatabaseCandidates));
        Assert.False(viewModel.StartCommand.CanExecute(null));

        await viewModel.ConfirmDatabaseAsync(candidate);

        Assert.Equal(CollectionViewModelState.DatabaseConfirmed, viewModel.State);
        Assert.False(viewModel.IsDatabaseConfirmationVisible);
        Assert.Same(candidate, viewModel.SelectedDatabaseCandidate);
        Assert.Single(service.Requests);
        Assert.Single(confirmationService.Confirmations);
    }

    [Fact]
    public async Task Multiple_database_candidates_are_confirmed_and_persisted_one_at_a_time()
    {
        var postgresql = CreateDatabaseCandidate("PostgreSQL", string.Empty, "postgresql.service");
        var mysql = CreateDatabaseCandidate("MySQL", string.Empty, "mysql.service");
        var workflow = new FakeCollectionWorkflowService(
            CollectionWorkflowResult.RequiresDatabaseConfirmation(new[] { postgresql, mysql }));
        var confirmationService = new FakeDatabaseConfirmationService();
        var viewModel = CreateReadyViewModel(workflow, confirmationService);
        await viewModel.StartAsync();

        await viewModel.ConfirmDatabaseAsync(postgresql);

        Assert.Equal(CollectionViewModelState.AwaitingDatabaseConfirmation, viewModel.State);
        Assert.Same(mysql, Assert.Single(viewModel.DatabaseCandidates));
        Assert.Single(confirmationService.Confirmations);
        Assert.Contains("仍有 1 个候选", viewModel.ProgressMessage);

        await viewModel.ConfirmDatabaseAsync(mysql);

        Assert.Equal(CollectionViewModelState.DatabaseConfirmed, viewModel.State);
        Assert.Empty(viewModel.DatabaseCandidates);
        Assert.Equal(2, confirmationService.Confirmations.Count);
        Assert.Contains("均已完成", viewModel.ProgressMessage);
    }

    [Fact]
    public async Task Host_software_candidates_are_confirmed_or_rejected_one_at_a_time()
    {
        var project = CreateProject();
        var device = CreateDevice(project);
        var batch = CreateHostSoftwareBatch(project, device);
        var workflow = new FakeCollectionWorkflowService(
            CollectionWorkflowResult.RequiresHostSoftwareConfirmation(
                Array.Empty<DatabaseInstanceCandidate>(),
                Array.Empty<MiddlewareInstanceCandidate>(),
                batch));
        var confirmations = new FakeHostSoftwareConfirmationService();
        var viewModel = new CollectionViewModel(
            workflow,
            new FakeDatabaseConfirmationService(),
            null,
            confirmations);
        viewModel.SelectProject(project);
        viewModel.SelectDevice(new CollectionDeviceSelection(
            device,
            true,
            CreateHostKeyTrust(device.Host, device.Port, HostKeyTrustState.Verified)));
        SelectGenericLinuxAdapter(viewModel);

        await viewModel.StartAsync();

        Assert.True(viewModel.IsHostSoftwareConfirmationVisible);
        Assert.False(viewModel.IsDatabaseConfirmationVisible);
        Assert.Equal(2, viewModel.HostSoftwareCandidates.Count);
        await viewModel.ConfirmHostSoftwareAsync(batch.Candidates[0]);
        Assert.Single(viewModel.HostSoftwareCandidates);
        Assert.Contains("已确认", viewModel.ProgressMessage);

        await viewModel.RejectHostSoftwareAsync(batch.Candidates[1]);

        Assert.Equal(CollectionViewModelState.DatabaseConfirmed, viewModel.State);
        Assert.Empty(viewModel.HostSoftwareCandidates);
        Assert.Single(confirmations.Confirmed);
        Assert.Single(confirmations.Rejected);
        Assert.Contains("不是本次测评目标", confirmations.Rejected[0].Reason);
    }

    [Fact]
    public async Task Pending_host_software_candidates_are_restored_after_identity_lookup()
    {
        var project = CreateProject();
        var device = CreateDevice(project);
        var batch = CreateHostSoftwareBatch(project, device);
        var pending = new PendingHostSoftwareDiscoveryBatchRecord(batch, batch.Candidates);
        var viewModel = new CollectionViewModel(
            new FakeCollectionWorkflowService(),
            new FakeDatabaseConfirmationService(),
            new FakePendingIdentificationRepository(null),
            new FakeHostSoftwareConfirmationService(),
            new FakePendingHostSoftwareRepository(pending));
        viewModel.SelectProject(project);
        viewModel.SelectDevice(new CollectionDeviceSelection(
            device,
            true,
            CreateHostKeyTrust(device.Host, device.Port, HostKeyTrustState.Verified)));

        await viewModel.RestorePendingIdentificationAsync(device);

        Assert.Equal(CollectionViewModelState.AwaitingDatabaseConfirmation, viewModel.State);
        Assert.True(viewModel.IsHostSoftwareConfirmationVisible);
        Assert.Equal(batch.Candidates.Select(item => item.CandidateId),
            viewModel.HostSoftwareCandidates.Select(item => item.CandidateId));
        Assert.False(viewModel.StartCommand.CanExecute(null));
        Assert.Contains("已恢复", viewModel.ProgressMessage);
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

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => viewModel.ConfirmDatabaseAsync(other));

        Assert.Equal("只能确认当前数据库候选项。", error.Message);
        Assert.Null(viewModel.SelectedDatabaseCandidate);
        Assert.Equal(CollectionViewModelState.AwaitingDatabaseConfirmation, viewModel.State);
        Assert.Single(service.Requests);
    }

    [Fact]
    public async Task Database_confirmation_stays_pending_when_audit_persistence_fails()
    {
        var candidate = CreateDatabaseCandidate("PostgreSQL", string.Empty, "postgresql.service");
        var workflow = new FakeCollectionWorkflowService(
            CollectionWorkflowResult.RequiresDatabaseConfirmation(new[] { candidate }));
        var confirmationService = new FakeDatabaseConfirmationService(
            new InvalidOperationException("fixture persistence failure"));
        var viewModel = CreateReadyViewModel(workflow, confirmationService);
        await viewModel.StartAsync();

        await viewModel.ConfirmDatabaseAsync(candidate);

        Assert.Equal(CollectionViewModelState.AwaitingDatabaseConfirmation, viewModel.State);
        Assert.Null(viewModel.SelectedDatabaseCandidate);
        Assert.NotNull(viewModel.Error);
        Assert.Equal("数据库确认记录保存失败", viewModel.Error!.Summary);
        Assert.Equal("InvalidOperationException", viewModel.Error.TechnicalDetails);
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

    private static CollectionViewModel CreateReadyViewModel(
        ICollectionWorkflowService service,
        IDatabaseConfirmationService? confirmationService = null)
    {
        var project = CreateProject();
        var viewModel = new CollectionViewModel(
            service,
            confirmationService ?? new FakeDatabaseConfirmationService());
        viewModel.SelectProject(project);
        viewModel.SelectDevice(CreateSelection(project, componentAvailable: true, HostKeyTrustState.Verified));
        SelectGenericLinuxAdapter(viewModel);
        return viewModel;
    }

    private static void SelectGenericLinuxAdapter(CollectionViewModel viewModel)
    {
        viewModel.SelectedAdapterOption = Assert.Single(
            viewModel.AdapterOptions,
            item => item.Id == CollectionAdapterId.GenericLinux);
    }

    private static HostSoftwareDiscoveryBatchRecord CreateHostSoftwareBatch(
        ProjectRecord project,
        DeviceRecord device)
    {
        var batchId = Guid.NewGuid();
        var taskId = CollectionTaskId.New();
        var candidates = new[]
        {
            CreateStoredHostSoftwareCandidate(
                batchId, taskId, 0, HostSoftwareCategory.Database, "PostgreSQL", "16", "postgresql.service"),
            CreateStoredHostSoftwareCandidate(
                batchId, taskId, 1, HostSoftwareCategory.Middleware, "Apache Tomcat", "9", "tomcat9.service")
        };
        return new HostSoftwareDiscoveryBatchRecord(
            batchId,
            project.Id,
            device.Id,
            taskId,
            1,
            null,
            "test-read-only-discovery",
            candidates,
            DateTimeOffset.UtcNow);
    }

    private static HostSoftwareDiscoveryCandidateRecord CreateStoredHostSoftwareCandidate(
        Guid batchId,
        CollectionTaskId taskId,
        int ordinal,
        HostSoftwareCategory category,
        string product,
        string version,
        string instanceName)
    {
        var candidateId = Guid.NewGuid();
        var source = new HostSoftwareDiscoveryEvidenceRecord(
            Guid.NewGuid(),
            candidateId,
            0,
            taskId,
            ordinal,
            HostSoftwareEvidenceKind.Service,
            "database-host-discovery-linux-services",
            instanceName + " loaded active running",
            new string('a', 64));
        return new HostSoftwareDiscoveryCandidateRecord(
            candidateId,
            batchId,
            ordinal,
            category,
            product,
            version,
            HostSoftwareInstallationType.LocalService,
            instanceName,
            null,
            0.9,
            new[] { source });
    }

    private sealed class FakeDatabaseConfirmationService : IDatabaseConfirmationService
    {
        private readonly Exception? exception;

        public FakeDatabaseConfirmationService(Exception? exception = null)
        {
            this.exception = exception;
        }

        public List<DatabaseConfirmationRecord> Confirmations { get; } =
            new List<DatabaseConfirmationRecord>();

        public Task<DatabaseConfirmationRecord> ConfirmAsync(
            ProjectRecord project,
            DeviceRecord device,
            DatabaseInstanceCandidate candidate,
            CancellationToken cancellationToken = default)
        {
            if (exception != null)
            {
                throw exception;
            }

            var record = new DatabaseConfirmationRecord(
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
                "测试人工确认");
            Confirmations.Add(record);
            return Task.FromResult(record);
        }
    }

    private sealed class FakeHostSoftwareConfirmationService :
        IHostSoftwareCandidateConfirmationService
    {
        internal List<HostSoftwareCandidateDecisionRecord> Confirmed { get; } =
            new List<HostSoftwareCandidateDecisionRecord>();
        internal List<HostSoftwareCandidateDecisionRecord> Rejected { get; } =
            new List<HostSoftwareCandidateDecisionRecord>();

        public Task<HostSoftwareCandidateDecisionRecord> ConfirmAsync(
            HostSoftwareDiscoveryCandidateRecord candidate,
            CancellationToken cancellationToken = default)
        {
            var record = CreateDecision(candidate, HostSoftwareCandidateDecision.Confirmed, null);
            Confirmed.Add(record);
            return Task.FromResult(record);
        }

        public Task<HostSoftwareCandidateDecisionRecord> RejectAsync(
            HostSoftwareDiscoveryCandidateRecord candidate,
            string reason,
            CancellationToken cancellationToken = default)
        {
            var record = CreateDecision(candidate, HostSoftwareCandidateDecision.Rejected, reason);
            Rejected.Add(record);
            return Task.FromResult(record);
        }

        private static HostSoftwareCandidateDecisionRecord CreateDecision(
            HostSoftwareDiscoveryCandidateRecord candidate,
            HostSoftwareCandidateDecision decision,
            string? reason)
        {
            return new HostSoftwareCandidateDecisionRecord(
                Guid.NewGuid(),
                candidate.CandidateId,
                decision,
                "TEST\\assessor",
                "view-model-test",
                reason,
                DateTimeOffset.UtcNow);
        }
    }

    private sealed class FakePendingHostSoftwareRepository :
        IPendingHostSoftwareDiscoveryRepository
    {
        private readonly PendingHostSoftwareDiscoveryBatchRecord? pending;

        internal FakePendingHostSoftwareRepository(
            PendingHostSoftwareDiscoveryBatchRecord? pending)
        {
            this.pending = pending;
        }

        public Task<PendingHostSoftwareDiscoveryBatchRecord?> GetLatestPendingHostSoftwareDiscoveryBatchAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                pending != null && pending.Batch.DeviceId.Equals(deviceId) ? pending : null);
        }
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
        return CreateDevice(project, TargetCategory.Automatic);
    }

    private static DeviceRecord CreateDevice(ProjectRecord project, TargetCategory category)
    {
        return new DeviceRecord(
            DeviceId.New(),
            project.Id,
            "设备",
            "192.0.2.10",
            22,
            "audit-user",
            category,
            ConnectionProtocol.Ssh,
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
            TargetCategory.Server,
            "ubuntu",
            null,
            model,
            "24.04",
            "ID=ubuntu",
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
            "100 " + processName,
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

    private sealed class FakePendingIdentificationRepository : IPendingDeviceIdentificationRepository
    {
        private readonly PendingDeviceIdentificationBatch? pending;

        public FakePendingIdentificationRepository(PendingDeviceIdentificationBatch? pending)
        {
            this.pending = pending;
        }

        public Task<PendingDeviceIdentificationBatch> AppendPendingDeviceIdentificationAsync(
            DeviceId deviceId,
            IReadOnlyList<DetectionCandidate> candidates,
            Guid? supersededBatchId,
            DateTimeOffset recordedAt,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<PendingDeviceIdentificationBatch?> GetLatestPendingDeviceIdentificationAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                pending != null && pending.DeviceId.Equals(deviceId) ? pending : null);
        }

        public Task ResolvePendingDeviceIdentificationAsync(
            DeviceId deviceId,
            Guid batchId,
            PendingIdentificationResolution resolution,
            DateTimeOffset resolvedAt,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<DeviceIdentificationRecord> CompletePendingDeviceIdentificationAsync(
            DeviceId deviceId,
            Guid batchId,
            DetectionCandidate confirmedCandidate,
            string confirmationSource,
            DateTimeOffset recordedAt,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class BlockingPendingIdentificationRepository : IPendingDeviceIdentificationRepository
    {
        private readonly TaskCompletionSource<PendingDeviceIdentificationBatch?> completion =
            new TaskCompletionSource<PendingDeviceIdentificationBatch?>(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<bool> Started { get; } =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Complete(PendingDeviceIdentificationBatch? value)
        {
            completion.TrySetResult(value);
        }

        public Task<PendingDeviceIdentificationBatch?> GetLatestPendingDeviceIdentificationAsync(
            DeviceId deviceId,
            CancellationToken cancellationToken = default)
        {
            Started.TrySetResult(true);
            return completion.Task;
        }

        public Task<PendingDeviceIdentificationBatch> AppendPendingDeviceIdentificationAsync(
            DeviceId deviceId,
            IReadOnlyList<DetectionCandidate> candidates,
            Guid? supersededBatchId,
            DateTimeOffset recordedAt,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task ResolvePendingDeviceIdentificationAsync(
            DeviceId deviceId,
            Guid batchId,
            PendingIdentificationResolution resolution,
            DateTimeOffset resolvedAt,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<DeviceIdentificationRecord> CompletePendingDeviceIdentificationAsync(
            DeviceId deviceId,
            Guid batchId,
            DetectionCandidate confirmedCandidate,
            string confirmationSource,
            DateTimeOffset recordedAt,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
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
