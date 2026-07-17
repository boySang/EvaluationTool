using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.App.ViewModels;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Windows.Tests.ViewModels;

public sealed class ProjectWorkspaceViewModelTests
{
    [Fact]
    public async Task Initialize_loads_projects_and_enters_ready_state()
    {
        var project = CreateProject("项目甲");
        var service = new FakeProjectWorkspaceService { Projects = new[] { project } };
        var viewModel = new ProjectWorkspaceViewModel(service);

        await viewModel.InitializeAsync();

        Assert.Equal(ProjectWorkspaceState.Ready, viewModel.State);
        Assert.Equal(new[] { project }, viewModel.Projects);
        Assert.Null(viewModel.SelectedProject);
    }

    [Fact]
    public async Task Create_project_refreshes_projects_and_selects_created_project()
    {
        var existing = CreateProject("已有项目");
        var created = CreateProject("新项目");
        var service = new FakeProjectWorkspaceService
        {
            Projects = new[] { existing },
            CreatedProjectId = created.Id
        };
        service.AfterCreate = () => service.Projects = new[] { existing, created };
        var viewModel = new ProjectWorkspaceViewModel(service)
        {
            CustomerName = " 客户 ",
            ProjectName = " 新项目 ",
            EvidenceRoot = @"C:\Evidence"
        };

        await viewModel.CreateProjectAsync();

        Assert.Equal((" 客户 ", " 新项目 ", @"C:\Evidence"), service.CreateArguments);
        Assert.Same(created, viewModel.SelectedProject);
        Assert.Equal(new[] { existing, created }, viewModel.Projects);
        Assert.Empty(viewModel.Devices);
    }

    [Fact]
    public async Task Selecting_project_clears_old_device_before_loading_new_devices()
    {
        var first = CreateProject("项目甲");
        var second = CreateProject("项目乙");
        var firstDevice = CreateDevice(first, "设备甲");
        var secondLoad = new TaskCompletionSource<IReadOnlyList<DeviceRecord>>();
        var service = new FakeProjectWorkspaceService();
        service.DeviceLoads[first.Id] = Task.FromResult<IReadOnlyList<DeviceRecord>>(new[] { firstDevice });
        service.DeviceLoads[second.Id] = secondLoad.Task;
        var viewModel = new ProjectWorkspaceViewModel(service);
        await viewModel.SelectProjectAsync(first);
        viewModel.SelectedDevice = firstDevice;

        var selecting = viewModel.SelectProjectAsync(second);

        Assert.Same(second, viewModel.SelectedProject);
        Assert.Null(viewModel.SelectedDevice);
        Assert.Empty(viewModel.Devices);
        secondLoad.SetResult(Array.Empty<DeviceRecord>());
        await selecting;
    }

    [Fact]
    public async Task Older_project_load_cannot_overwrite_newer_selection()
    {
        var first = CreateProject("项目甲");
        var second = CreateProject("项目乙");
        var firstDevice = CreateDevice(first, "旧结果");
        var secondDevice = CreateDevice(second, "新结果");
        var firstLoad = new TaskCompletionSource<IReadOnlyList<DeviceRecord>>();
        var service = new FakeProjectWorkspaceService();
        service.DeviceLoads[first.Id] = firstLoad.Task;
        service.DeviceLoads[second.Id] = Task.FromResult<IReadOnlyList<DeviceRecord>>(new[] { secondDevice });
        var viewModel = new ProjectWorkspaceViewModel(service);

        var older = viewModel.SelectProjectAsync(first);
        await viewModel.SelectProjectAsync(second);
        firstLoad.SetResult(new[] { firstDevice });
        await older;

        Assert.Same(second, viewModel.SelectedProject);
        Assert.Equal(new[] { secondDevice }, viewModel.Devices);
    }

    [Fact]
    public async Task Add_device_uses_fields_then_refreshes_and_selects_created_device()
    {
        var project = CreateProject("项目");
        var createdDevice = CreateDevice(project, "交换机");
        var service = new FakeProjectWorkspaceService { CreatedDeviceId = createdDevice.Id };
        service.DeviceLoads[project.Id] = Task.FromResult<IReadOnlyList<DeviceRecord>>(Array.Empty<DeviceRecord>());
        service.AfterAdd = () => service.DeviceLoads[project.Id] =
            Task.FromResult<IReadOnlyList<DeviceRecord>>(new[] { createdDevice });
        var viewModel = new ProjectWorkspaceViewModel(service)
        {
            DeviceDisplayName = "交换机",
            DeviceHost = "192.0.2.10",
            DevicePortText = "22",
            DeviceUserName = "audit-reader",
            DeviceCategory = TargetCategory.NetworkDevice
        };
        await viewModel.SelectProjectAsync(project);
        var password = "temporary-secret".ToCharArray();

        await viewModel.AddDeviceAsync(password);

        Assert.Equal(
            (project.Id, "交换机", "192.0.2.10", 22, "audit-reader", TargetCategory.NetworkDevice),
            service.AddArguments);
        Assert.Same(createdDevice, viewModel.SelectedDevice);
        Assert.All(password, value => Assert.Equal('\0', value));
    }

    [Fact]
    public async Task Add_private_key_device_uses_private_key_service_then_clears_material()
    {
        var project = CreateProject("项目");
        var createdDevice = CreateDevice(project, "服务器");
        var service = new FakeProjectWorkspaceService { CreatedDeviceId = createdDevice.Id };
        service.DeviceLoads[project.Id] = Task.FromResult<IReadOnlyList<DeviceRecord>>(Array.Empty<DeviceRecord>());
        service.AfterAdd = () => service.DeviceLoads[project.Id] =
            Task.FromResult<IReadOnlyList<DeviceRecord>>(new[] { createdDevice });
        var viewModel = new ProjectWorkspaceViewModel(service)
        {
            DeviceDisplayName = "服务器",
            DeviceHost = "192.0.2.20",
            DevicePortText = "22",
            DeviceUserName = "audit-reader",
            DeviceCategory = TargetCategory.Server
        };
        await viewModel.SelectProjectAsync(project);
        var privateKeyMaterial = "private-key-material".ToCharArray();

        await viewModel.AddPrivateKeyDeviceAsync(privateKeyMaterial);

        Assert.Equal(
            (project.Id, "服务器", "192.0.2.20", 22, "audit-reader", TargetCategory.Server),
            service.PrivateKeyAddArguments);
        Assert.Equal(1, service.PrivateKeyAddCallCount);
        Assert.Same(createdDevice, viewModel.SelectedDevice);
        Assert.All(privateKeyMaterial, value => Assert.Equal('\0', value));
    }

    [Fact]
    public async Task Operations_reject_duplicate_submission_while_busy()
    {
        var createGate = new TaskCompletionSource<ProjectId>();
        var service = new FakeProjectWorkspaceService { CreateGate = createGate.Task };
        var viewModel = new ProjectWorkspaceViewModel(service)
        {
            CustomerName = "客户",
            ProjectName = "项目",
            EvidenceRoot = @"C:\Evidence"
        };

        var first = viewModel.CreateProjectAsync();
        var duplicate = viewModel.CreateProjectAsync();

        Assert.Equal(1, service.CreateCallCount);
        await duplicate;
        createGate.SetResult(ProjectId.New());
        await first;
    }

    [Fact]
    public async Task Project_selection_is_frozen_while_device_is_being_saved()
    {
        var first = CreateProject("项目甲");
        var second = CreateProject("项目乙");
        var createdDevice = CreateDevice(first, "设备甲");
        var addGate = new TaskCompletionSource<DeviceId>(TaskCreationOptions.RunContinuationsAsynchronously);
        var service = new FakeProjectWorkspaceService { AddGate = addGate.Task };
        service.DeviceLoads[first.Id] = Task.FromResult<IReadOnlyList<DeviceRecord>>(Array.Empty<DeviceRecord>());
        service.DeviceLoads[second.Id] = Task.FromResult<IReadOnlyList<DeviceRecord>>(Array.Empty<DeviceRecord>());
        service.AfterAdd = () => service.DeviceLoads[first.Id] =
            Task.FromResult<IReadOnlyList<DeviceRecord>>(new[] { createdDevice });
        var viewModel = new ProjectWorkspaceViewModel(service)
        {
            DeviceDisplayName = "设备甲",
            DeviceHost = "192.0.2.10",
            DevicePortText = "22"
        };
        await viewModel.SelectProjectAsync(first);

        var saving = viewModel.AddDeviceAsync("临时口令".ToCharArray());
        await viewModel.SelectProjectAsync(second);

        Assert.Same(first, viewModel.SelectedProject);
        addGate.SetResult(createdDevice.Id);
        await saving;
        Assert.Same(createdDevice, viewModel.SelectedDevice);
    }

    [Fact]
    public async Task Create_project_keeps_failed_state_when_initial_device_load_fails()
    {
        var created = CreateProject("新项目");
        var service = new FakeProjectWorkspaceService { CreatedProjectId = created.Id };
        service.AfterCreate = () =>
        {
            service.Projects = new[] { created };
            service.DeviceLoads[created.Id] = Task.FromException<IReadOnlyList<DeviceRecord>>(
                new InvalidOperationException("device load failed"));
        };
        var viewModel = new ProjectWorkspaceViewModel(service)
        {
            CustomerName = "客户",
            ProjectName = "项目",
            EvidenceRoot = @"C:\Evidence"
        };

        await viewModel.CreateProjectAsync();

        Assert.Equal(ProjectWorkspaceState.Failed, viewModel.State);
        Assert.Equal(nameof(InvalidOperationException), viewModel.TechnicalDetails);
    }

    [Fact]
    public async Task Failure_exposes_structured_message_and_only_exception_type_as_details()
    {
        var service = new FakeProjectWorkspaceService
        {
            InitializeError = new InvalidOperationException("password=super-secret")
        };
        var viewModel = new ProjectWorkspaceViewModel(service);

        await viewModel.InitializeAsync();

        Assert.Equal(ProjectWorkspaceState.Failed, viewModel.State);
        Assert.NotEmpty(viewModel.WhatHappened);
        Assert.NotEmpty(viewModel.PossibleCause);
        Assert.NotEmpty(viewModel.HowToFix);
        Assert.Equal(nameof(InvalidOperationException), viewModel.TechnicalDetails);
        Assert.DoesNotContain("super-secret", string.Join(" ", viewModel.WhatHappened,
            viewModel.PossibleCause, viewModel.HowToFix, viewModel.TechnicalDetails));
    }

    [Fact]
    public void View_model_does_not_hold_plaintext_password_properties_or_fields()
    {
        var type = typeof(ProjectWorkspaceViewModel);
        Assert.DoesNotContain(type.GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic),
            property => IsSecretStorage(property.Name, property.PropertyType));
        Assert.DoesNotContain(type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic),
            field => IsSecretStorage(field.Name, field.FieldType));
    }

    private static bool IsSecretStorage(string name, Type type)
    {
        return (name.IndexOf("password", StringComparison.OrdinalIgnoreCase) >= 0
                || name.IndexOf("secret", StringComparison.OrdinalIgnoreCase) >= 0
                || name.IndexOf("privatekey", StringComparison.OrdinalIgnoreCase) >= 0)
            && (type == typeof(string) || type == typeof(char[]));
    }

    private static ProjectRecord CreateProject(string name)
    {
        return new ProjectRecord(ProjectId.New(), "客户", name, @"C:\Evidence", DateTimeOffset.UtcNow);
    }

    private static DeviceRecord CreateDevice(ProjectRecord project, string name)
    {
        return new DeviceRecord(DeviceId.New(), project.Id, name, "192.0.2.10", 22,
            CredentialReference.New(), DateTimeOffset.UtcNow);
    }

    private sealed class FakeProjectWorkspaceService : IProjectWorkspaceService
    {
        public IReadOnlyList<ProjectRecord> Projects { get; set; } = Array.Empty<ProjectRecord>();
        public Dictionary<ProjectId, Task<IReadOnlyList<DeviceRecord>>> DeviceLoads { get; } =
            new Dictionary<ProjectId, Task<IReadOnlyList<DeviceRecord>>>();
        public ProjectId CreatedProjectId { get; set; } = ProjectId.New();
        public DeviceId CreatedDeviceId { get; set; } = DeviceId.New();
        public Exception? InitializeError { get; set; }
        public Task<ProjectId>? CreateGate { get; set; }
        public Task<DeviceId>? AddGate { get; set; }
        public Action? AfterCreate { get; set; }
        public Action? AfterAdd { get; set; }
        public int CreateCallCount { get; private set; }
        public (string Customer, string Project, string Root) CreateArguments { get; private set; }
        public (ProjectId Project, string Name, string Host, int Port, string UserName, TargetCategory Category) AddArguments { get; private set; }
        public (ProjectId Project, string Name, string Host, int Port, string UserName, TargetCategory Category) PrivateKeyAddArguments { get; private set; }
        public int PrivateKeyAddCallCount { get; private set; }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            return InitializeError == null ? Task.CompletedTask : Task.FromException(InitializeError);
        }

        public Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Projects);
        }

        public async Task<ProjectId> CreateProjectAsync(string customerName, string projectName,
            string evidenceRoot, CancellationToken cancellationToken = default)
        {
            CreateCallCount++;
            CreateArguments = (customerName, projectName, evidenceRoot);
            var id = CreateGate == null ? CreatedProjectId : await CreateGate;
            AfterCreate?.Invoke();
            return id;
        }

        public Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            return DeviceLoads.TryGetValue(projectId, out var result)
                ? result
                : Task.FromResult<IReadOnlyList<DeviceRecord>>(Array.Empty<DeviceRecord>());
        }

        public async Task<DeviceId> AddDeviceAsync(ProjectId projectId, string displayName, string host, int port,
            char[] password, CancellationToken cancellationToken = default)
        {
            return await AddSshDeviceAsync(
                projectId, displayName, host, port, "未设置", TargetCategory.Automatic,
                password, cancellationToken);
        }

        public async Task<DeviceId> AddSshDeviceAsync(
            ProjectId projectId,
            string displayName,
            string host,
            int port,
            string userName,
            TargetCategory category,
            char[] password,
            CancellationToken cancellationToken = default)
        {
            AddArguments = (projectId, displayName, host, port, userName, category);
            var id = AddGate == null ? CreatedDeviceId : await AddGate;
            AfterAdd?.Invoke();
            return id;
        }

        public async Task<DeviceId> AddSshPrivateKeyDeviceAsync(
            ProjectId projectId,
            string displayName,
            string host,
            int port,
            string userName,
            TargetCategory category,
            char[] privateKeyMaterial,
            CancellationToken cancellationToken = default)
        {
            PrivateKeyAddCallCount++;
            PrivateKeyAddArguments = (projectId, displayName, host, port, userName, category);
            var id = AddGate == null ? CreatedDeviceId : await AddGate;
            AfterAdd?.Invoke();
            return id;
        }
    }
}
