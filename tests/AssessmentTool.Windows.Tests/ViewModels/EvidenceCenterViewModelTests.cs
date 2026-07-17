using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Xunit;

namespace AssessmentTool.Windows.Tests.ViewModels;

public sealed class EvidenceCenterViewModelTests
{
    [Fact]
    public async Task Selecting_project_loads_items_and_enables_refresh()
    {
        var project = CreateProject("项目甲");
        var item = CreateItem("command-1");
        var service = new FakeEvidenceCenterService(
            Task.FromResult(new EvidenceCenterSnapshot(project.Id, new[] { item })));
        var viewModel = new EvidenceCenterViewModel(service);

        await viewModel.SelectProjectAsync(project);

        Assert.Same(project, viewModel.SelectedProject);
        Assert.Equal(EvidenceCenterViewModelState.Ready, viewModel.State);
        Assert.Same(item, Assert.Single(viewModel.Items));
        Assert.True(viewModel.HasItems);
        Assert.True(viewModel.CanRefresh);
        Assert.True(viewModel.RefreshCommand.CanExecute(null));
        Assert.Equal(project.Id, Assert.Single(service.RequestedProjectIds));
    }

    [Fact]
    public async Task Refresh_reloads_current_project_and_replaces_snapshot()
    {
        var project = CreateProject("项目甲");
        var first = CreateItem("first");
        var second = CreateItem("second");
        var service = new FakeEvidenceCenterService(
            Task.FromResult(new EvidenceCenterSnapshot(project.Id, new[] { first })),
            Task.FromResult(new EvidenceCenterSnapshot(project.Id, new[] { second })));
        var viewModel = new EvidenceCenterViewModel(service);
        await viewModel.SelectProjectAsync(project);

        await viewModel.RefreshAsync();

        Assert.Same(second, Assert.Single(viewModel.Items));
        Assert.Equal(2, service.RequestedProjectIds.Count);
        Assert.Equal(EvidenceCenterViewModelState.Ready, viewModel.State);
    }

    [Fact]
    public async Task Confirmation_only_snapshot_is_ready_and_exposes_audit_history()
    {
        var project = CreateProject("项目甲");
        var confirmation = new DatabaseConfirmationAuditItem(
            "Linux服务器甲",
            "PostgreSQL",
            "16.3",
            DatabaseInstallationType.Container,
            "postgres-main",
            "15432->5432/tcp",
            "容器名称、镜像和端口元数据",
            0.91,
            DateTimeOffset.UtcNow,
            "测评人员人工确认");
        var service = new FakeEvidenceCenterService(Task.FromResult(
            new EvidenceCenterSnapshot(
                project.Id,
                Array.Empty<EvidenceCenterItem>(),
                new[] { confirmation })));
        var viewModel = new EvidenceCenterViewModel(service);

        await viewModel.SelectProjectAsync(project);

        Assert.Equal(EvidenceCenterViewModelState.Ready, viewModel.State);
        Assert.Empty(viewModel.Items);
        Assert.True(viewModel.HasDatabaseConfirmations);
        Assert.Same(confirmation, Assert.Single(viewModel.DatabaseConfirmations));
        Assert.False(viewModel.CanVerify);
    }

    [Fact]
    public async Task Host_software_only_snapshot_is_ready_and_exposes_full_decision_history()
    {
        var project = CreateProject("项目甲");
        var discovery = new HostSoftwareDiscoveryAuditItem(
            "Linux服务器甲",
            2,
            DateTimeOffset.UtcNow.AddMinutes(-2),
            HostSoftwareCategory.Middleware,
            "Apache Tomcat",
            "9",
            HostSoftwareInstallationType.LocalService,
            "tomcat9.service",
            "8080/tcp",
            0.91,
            "服务：tomcat9.service loaded active running",
            HostSoftwareAuditDecisionStatus.Confirmed,
            "CONTOSO\\assessor",
            "候选确认界面",
            null,
            DateTimeOffset.UtcNow);
        var service = new FakeEvidenceCenterService(Task.FromResult(
            new EvidenceCenterSnapshot(
                project.Id,
                Array.Empty<EvidenceCenterItem>(),
                Array.Empty<DatabaseConfirmationAuditItem>(),
                new[] { discovery })));
        var viewModel = new EvidenceCenterViewModel(service);

        await viewModel.SelectProjectAsync(project);

        Assert.Equal(EvidenceCenterViewModelState.Ready, viewModel.State);
        Assert.True(viewModel.HasHostSoftwareDiscoveries);
        Assert.Same(discovery, Assert.Single(viewModel.HostSoftwareDiscoveries));
        Assert.False(viewModel.CanVerify);
    }

    [Fact]
    public async Task Concurrent_refresh_is_single_flight()
    {
        var project = CreateProject("项目甲");
        var initial = new EvidenceCenterSnapshot(project.Id, Array.Empty<EvidenceCenterItem>());
        var pending = new TaskCompletionSource<EvidenceCenterSnapshot>();
        var service = new FakeEvidenceCenterService(Task.FromResult(initial), pending.Task);
        var viewModel = new EvidenceCenterViewModel(service);
        await viewModel.SelectProjectAsync(project);

        var first = viewModel.RefreshAsync();
        var second = viewModel.RefreshAsync();

        Assert.Same(first, second);
        Assert.Equal(EvidenceCenterViewModelState.Loading, viewModel.State);
        Assert.False(viewModel.RefreshCommand.CanExecute(null));
        Assert.Equal(2, service.RequestedProjectIds.Count);
        pending.SetResult(initial);
        await first;
        Assert.Equal(EvidenceCenterViewModelState.Empty, viewModel.State);
    }

    [Fact]
    public async Task Late_result_from_previous_project_cannot_replace_current_project()
    {
        var firstProject = CreateProject("项目甲");
        var secondProject = CreateProject("项目乙");
        var firstPending = new TaskCompletionSource<EvidenceCenterSnapshot>();
        var secondItem = CreateItem("second-project");
        var service = new FakeEvidenceCenterService(
            firstPending.Task,
            Task.FromResult(new EvidenceCenterSnapshot(secondProject.Id, new[] { secondItem })));
        var viewModel = new EvidenceCenterViewModel(service);

        var firstLoad = viewModel.SelectProjectAsync(firstProject);
        await viewModel.SelectProjectAsync(secondProject);
        firstPending.SetResult(new EvidenceCenterSnapshot(firstProject.Id, new[] { CreateItem("stale") }));
        await firstLoad;

        Assert.Same(secondProject, viewModel.SelectedProject);
        Assert.Same(secondItem, Assert.Single(viewModel.Items));
        Assert.Equal(EvidenceCenterViewModelState.Ready, viewModel.State);
    }

    [Fact]
    public async Task Selecting_no_project_clears_items_without_query()
    {
        var project = CreateProject("项目甲");
        var service = new FakeEvidenceCenterService(Task.FromResult(
            new EvidenceCenterSnapshot(project.Id, new[] { CreateItem("command") })));
        var viewModel = new EvidenceCenterViewModel(service);
        await viewModel.SelectProjectAsync(project);

        await viewModel.SelectProjectAsync(null);

        Assert.Null(viewModel.SelectedProject);
        Assert.Empty(viewModel.Items);
        Assert.False(viewModel.HasItems);
        Assert.Equal(EvidenceCenterViewModelState.NoProject, viewModel.State);
        Assert.False(viewModel.CanRefresh);
        Assert.Single(service.RequestedProjectIds);
    }

    [Fact]
    public async Task Failure_is_structured_and_does_not_expose_service_details()
    {
        var project = CreateProject("项目甲");
        var service = new FakeEvidenceCenterService(Task.FromException<EvidenceCenterSnapshot>(
            new InvalidOperationException(@"secret C:\customer\evidence.db")));
        var viewModel = new EvidenceCenterViewModel(service);

        await viewModel.SelectProjectAsync(project);

        Assert.Equal(EvidenceCenterViewModelState.Failed, viewModel.State);
        Assert.Equal("证据记录加载失败", viewModel.WhatHappened);
        Assert.Contains("数据库", viewModel.PossibleCause, StringComparison.Ordinal);
        Assert.Contains("刷新", viewModel.HowToFix, StringComparison.Ordinal);
        Assert.Equal(nameof(InvalidOperationException), viewModel.TechnicalDetails);
        var visibleError = string.Join(" ", viewModel.WhatHappened, viewModel.PossibleCause,
            viewModel.HowToFix, viewModel.TechnicalDetails);
        Assert.DoesNotContain("secret", visibleError, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("customer", visibleError, StringComparison.OrdinalIgnoreCase);
        Assert.True(viewModel.CanRefresh);
    }

    [Fact]
    public async Task Verify_reloads_files_and_reports_summary()
    {
        var project = CreateProject("项目甲");
        var indexed = CreateItem("indexed");
        var verified = new EvidenceCenterItem(
            indexed.DeviceId,
            indexed.CommandId,
            indexed.CommandText,
            indexed.StartedAt,
            indexed.CompletedAt,
            indexed.ExecutionStatus,
            indexed.RawOutputPath,
            indexed.ScreenshotCount,
            EvidenceShaStatus.Verified);
        var service = new FakeEvidenceCenterService(
            Task.FromResult(new EvidenceCenterSnapshot(project.Id, new[] { indexed })),
            Task.FromResult(new EvidenceCenterSnapshot(project.Id, new[] { verified })));
        var viewModel = new EvidenceCenterViewModel(service);
        await viewModel.SelectProjectAsync(project);

        await viewModel.VerifyAsync();

        Assert.Equal(EvidenceShaStatus.Verified, Assert.Single(viewModel.Items).ShaStatus);
        Assert.Contains("1 条与索引 SHA-256 一致", viewModel.VerificationSummary, StringComparison.Ordinal);
        Assert.Single(service.VerifiedProjects);
        Assert.Equal(project.Id, service.VerifiedProjects[0]);
    }

    [Fact]
    public async Task Open_folder_uses_selected_project_and_sanitizes_failure()
    {
        var project = CreateProject("项目甲");
        var service = new FakeEvidenceCenterService(Task.FromResult(
            new EvidenceCenterSnapshot(project.Id, new[] { CreateItem("command") })));
        var launcher = new FakeFolderLauncher();
        var viewModel = new EvidenceCenterViewModel(service, launcher);
        await viewModel.SelectProjectAsync(project);

        await viewModel.OpenEvidenceFolderAsync();
        Assert.Equal(project.Id, Assert.Single(launcher.OpenedProjects));

        launcher.Error = new InvalidOperationException(@"secret C:\customer");
        await viewModel.OpenEvidenceFolderAsync();
        Assert.Equal(EvidenceCenterViewModelState.Failed, viewModel.State);
        Assert.Equal("证据目录打开失败", viewModel.WhatHappened);
        Assert.DoesNotContain("secret", string.Join(" ", viewModel.WhatHappened,
            viewModel.PossibleCause, viewModel.HowToFix, viewModel.TechnicalDetails),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Evidence_file_commands_only_route_indexed_item_paths_and_sanitize_failure()
    {
        var project = CreateProject("项目甲");
        var item = new EvidenceCenterItem(
            DeviceId.New().ToString(),
            "Linux服务器甲",
            "command-1",
            "hostname",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            ExecutionStatus.Succeeded,
            @"设备\原始输出.txt",
            new[] { @"设备\证据_001.png" },
            1,
            EvidenceShaStatus.Complete);
        var service = new FakeEvidenceCenterService(Task.FromResult(
            new EvidenceCenterSnapshot(project.Id, new[] { item })));
        var locator = new FakeEvidenceFileLocator();
        var viewModel = new EvidenceCenterViewModel(service, fileLocator: locator);
        await viewModel.SelectProjectAsync(project);

        Assert.True(viewModel.OpenRawOutputCommand.CanExecute(item));
        Assert.True(viewModel.OpenFirstScreenshotCommand.CanExecute(item));
        await viewModel.ShowEvidenceFileAsync(item.RawOutputPath);
        await viewModel.ShowEvidenceFileAsync(item.FirstScreenshotPath);

        Assert.Equal(
            new[] { @"设备\原始输出.txt", @"设备\证据_001.png" },
            locator.RelativePaths);
        Assert.All(locator.ProjectIds, id => Assert.Equal(project.Id, id));

        locator.Error = new InvalidOperationException(@"secret C:\customer");
        await viewModel.ShowEvidenceFileAsync(item.RawOutputPath);
        Assert.Equal(EvidenceCenterViewModelState.Failed, viewModel.State);
        Assert.Equal("证据文件定位失败", viewModel.WhatHappened);
        Assert.DoesNotContain("secret", string.Join(" ", viewModel.WhatHappened,
            viewModel.PossibleCause, viewModel.HowToFix, viewModel.TechnicalDetails),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Export_manifest_uses_explicit_destination_and_reports_sanitized_result()
    {
        var project = CreateProject("项目甲");
        var service = new FakeEvidenceCenterService(Task.FromResult(
            new EvidenceCenterSnapshot(project.Id, new[] { CreateItem("command") })));
        var exporter = new FakeManifestExporter();
        var picker = new FakeManifestFilePicker { Path = @"C:\Exports\项目甲.json" };
        var viewModel = new EvidenceCenterViewModel(
            service,
            manifestExporter: exporter,
            exportFilePicker: picker);
        await viewModel.SelectProjectAsync(project);

        Assert.True(viewModel.CanExportManifest);
        Assert.True(viewModel.ExportManifestCommand.CanExecute(null));
        await viewModel.ExportManifestAsync();

        Assert.Equal(project.Id, Assert.Single(exporter.Projects).Id);
        Assert.Equal(picker.Path, Assert.Single(exporter.Paths));
        Assert.Contains("已导出 1 条执行", viewModel.ExportSummary, StringComparison.Ordinal);
        Assert.Contains(picker.Path, viewModel.ExportSummary, StringComparison.Ordinal);
        Assert.Equal(EvidenceCenterViewModelState.Ready, viewModel.State);

        exporter.Error = new InvalidOperationException(@"secret C:\customer");
        await viewModel.ExportManifestAsync();
        Assert.Equal(EvidenceCenterViewModelState.Failed, viewModel.State);
        Assert.Equal("项目证据清单导出失败", viewModel.WhatHappened);
        Assert.DoesNotContain("secret", string.Join(" ", viewModel.WhatHappened,
            viewModel.PossibleCause, viewModel.HowToFix, viewModel.TechnicalDetails),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Export_manifest_cancel_does_not_start_export_or_change_ready_state()
    {
        var project = CreateProject("项目甲");
        var service = new FakeEvidenceCenterService(Task.FromResult(
            new EvidenceCenterSnapshot(project.Id, Array.Empty<EvidenceCenterItem>())));
        var exporter = new FakeManifestExporter();
        var viewModel = new EvidenceCenterViewModel(
            service,
            manifestExporter: exporter,
            exportFilePicker: new FakeManifestFilePicker());
        await viewModel.SelectProjectAsync(project);

        await viewModel.ExportManifestAsync();

        Assert.Empty(exporter.Projects);
        Assert.Equal(EvidenceCenterViewModelState.Empty, viewModel.State);
    }

    [Fact]
    public async Task Export_package_requires_evidence_and_reports_sanitized_result()
    {
        var project = CreateProject("项目甲");
        var service = new FakeEvidenceCenterService(Task.FromResult(
            new EvidenceCenterSnapshot(project.Id, new[] { CreateItem("command") })));
        var exporter = new FakePackageExporter();
        var picker = new FakePackageFilePicker { Path = @"C:\Exports\项目甲.zip" };
        var viewModel = new EvidenceCenterViewModel(
            service,
            packageExporter: exporter,
            packageExportFilePicker: picker);
        await viewModel.SelectProjectAsync(project);

        Assert.True(viewModel.CanExportPackage);
        Assert.True(viewModel.ExportPackageCommand.CanExecute(null));
        await viewModel.ExportPackageAsync();

        Assert.Equal(project.Id, Assert.Single(exporter.Projects).Id);
        Assert.Equal(picker.Path, Assert.Single(exporter.Paths));
        Assert.Contains("已打包 2 个已验证证据文件", viewModel.PackageExportSummary, StringComparison.Ordinal);
        Assert.Equal(EvidenceCenterViewModelState.Ready, viewModel.State);

        exporter.Error = new InvalidDataException(@"secret C:\customer");
        await viewModel.ExportPackageAsync();
        Assert.Equal(EvidenceCenterViewModelState.Failed, viewModel.State);
        Assert.Equal("项目证据包导出失败", viewModel.WhatHappened);
        Assert.DoesNotContain("secret", string.Join(" ", viewModel.WhatHappened,
            viewModel.PossibleCause, viewModel.HowToFix, viewModel.TechnicalDetails),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Export_package_is_disabled_for_project_without_execution_evidence()
    {
        var project = CreateProject("项目甲");
        var service = new FakeEvidenceCenterService(Task.FromResult(
            new EvidenceCenterSnapshot(project.Id, Array.Empty<EvidenceCenterItem>())));
        var viewModel = new EvidenceCenterViewModel(
            service,
            packageExporter: new FakePackageExporter(),
            packageExportFilePicker: new FakePackageFilePicker { Path = @"C:\Exports\empty.zip" });

        await viewModel.SelectProjectAsync(project);

        Assert.False(viewModel.CanExportPackage);
        Assert.False(viewModel.ExportPackageCommand.CanExecute(null));
    }

    [Fact]
    public async Task Recover_pending_evidence_reports_counts_and_refreshes_index()
    {
        var project = CreateProject("项目甲");
        var before = new EvidenceCenterSnapshot(project.Id, Array.Empty<EvidenceCenterItem>());
        var recoveredItem = CreateItem("recovered-command");
        var after = new EvidenceCenterSnapshot(project.Id, new[] { recoveredItem });
        var service = new FakeEvidenceCenterService(Task.FromResult(before), Task.FromResult(after));
        var recovery = new FakeEvidenceRecoveryService(
            new EvidenceRecoveryResult(2, 1, 1, 0));
        var viewModel = new EvidenceCenterViewModel(service, recoveryService: recovery);
        await viewModel.SelectProjectAsync(project);

        await viewModel.RecoverPendingEvidenceAsync();

        Assert.Equal(project.Id, Assert.Single(recovery.RequestedProjects));
        Assert.Same(recoveredItem, Assert.Single(viewModel.Items));
        Assert.Contains("成功恢复 1 个", viewModel.RecoverySummary, StringComparison.Ordinal);
        Assert.Contains("已在索引中 1 个", viewModel.RecoverySummary, StringComparison.Ordinal);
        Assert.Equal(EvidenceCenterViewModelState.Ready, viewModel.State);
        Assert.True(viewModel.RecoverCommand.CanExecute(null));
        Assert.Equal(2, service.RequestedProjectIds.Count);
    }

    private static ProjectRecord CreateProject(string name)
    {
        return new ProjectRecord(ProjectId.New(), "测试客户", name, @"C:\Evidence", DateTimeOffset.UtcNow);
    }

    private static EvidenceCenterItem CreateItem(string commandId)
    {
        return new EvidenceCenterItem(
            DeviceId.New().ToString(),
            commandId,
            "hostname",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            ExecutionStatus.Succeeded,
            @"设备\原始输出.txt",
            1,
            EvidenceShaStatus.Complete);
    }

    private sealed class FakeEvidenceCenterService : IEvidenceCenterService
    {
        private readonly Queue<Task<EvidenceCenterSnapshot>> results;

        internal FakeEvidenceCenterService(params Task<EvidenceCenterSnapshot>[] results)
        {
            this.results = new Queue<Task<EvidenceCenterSnapshot>>(results);
        }

        internal List<ProjectId> RequestedProjectIds { get; } = new List<ProjectId>();
        internal List<ProjectId> VerifiedProjects { get; } = new List<ProjectId>();

        public Task<EvidenceCenterSnapshot> LoadAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            RequestedProjectIds.Add(projectId);
            if (results.Count == 0)
            {
                throw new InvalidOperationException("测试未配置加载结果。");
            }

            return results.Dequeue();
        }

        public Task<EvidenceCenterSnapshot> VerifyAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            VerifiedProjects.Add(projectId);
            return LoadAsync(projectId, cancellationToken);
        }
    }

    private sealed class FakeEvidenceRecoveryService : IEvidenceRecoveryService
    {
        private readonly EvidenceRecoveryResult result;

        public FakeEvidenceRecoveryService(EvidenceRecoveryResult result)
        {
            this.result = result;
        }

        public List<ProjectId> RequestedProjects { get; } = new List<ProjectId>();

        public Task<EvidenceRecoveryResult> RecoverAsync(
            ProjectRecord project,
            CancellationToken cancellationToken = default)
        {
            RequestedProjects.Add(project.Id);
            return Task.FromResult(result);
        }
    }

    private sealed class FakeEvidenceFileLocator : IProjectEvidenceFileLocator
    {
        internal List<ProjectId> ProjectIds { get; } = new List<ProjectId>();
        internal List<string> RelativePaths { get; } = new List<string>();
        internal Exception? Error { get; set; }

        public Task ShowInFolderAsync(
            ProjectId projectId,
            string relativePath,
            CancellationToken cancellationToken = default)
        {
            ProjectIds.Add(projectId);
            RelativePaths.Add(relativePath);
            return Error == null ? Task.CompletedTask : Task.FromException(Error);
        }
    }

    private sealed class FakeManifestFilePicker : IEvidenceManifestExportFilePicker
    {
        internal string? Path { get; set; }

        public string? SelectDestination(ProjectRecord project) => Path;
    }

    private sealed class FakeManifestExporter : IProjectEvidenceManifestExporter
    {
        internal List<ProjectRecord> Projects { get; } = new List<ProjectRecord>();
        internal List<string> Paths { get; } = new List<string>();
        internal Exception? Error { get; set; }

        public Task<EvidenceManifestExportResult> ExportAsync(
            ProjectRecord project,
            string destinationPath,
            CancellationToken cancellationToken = default)
        {
            Projects.Add(project);
            Paths.Add(destinationPath);
            return Error == null
                ? Task.FromResult(new EvidenceManifestExportResult(destinationPath, 1, 2, 0))
                : Task.FromException<EvidenceManifestExportResult>(Error);
        }
    }

    private sealed class FakePackageFilePicker : IEvidencePackageExportFilePicker
    {
        internal string? Path { get; set; }

        public string? SelectDestination(ProjectRecord project) => Path;
    }

    private sealed class FakePackageExporter : IProjectEvidencePackageExporter
    {
        internal List<ProjectRecord> Projects { get; } = new List<ProjectRecord>();
        internal List<string> Paths { get; } = new List<string>();
        internal Exception? Error { get; set; }

        public Task<EvidencePackageExportResult> ExportAsync(
            ProjectRecord project,
            string destinationPath,
            CancellationToken cancellationToken = default)
        {
            Projects.Add(project);
            Paths.Add(destinationPath);
            return Error == null
                ? Task.FromResult(new EvidencePackageExportResult(destinationPath, 2, 2048))
                : Task.FromException<EvidencePackageExportResult>(Error);
        }
    }

    private sealed class FakeFolderLauncher : IProjectEvidenceFolderLauncher
    {
        internal List<ProjectId> OpenedProjects { get; } = new List<ProjectId>();
        internal Exception? Error { get; set; }

        public Task OpenAsync(ProjectId projectId, CancellationToken cancellationToken = default)
        {
            if (Error != null)
            {
                throw Error;
            }

            OpenedProjects.Add(projectId);
            return Task.CompletedTask;
        }
    }
}
