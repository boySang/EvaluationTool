using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Storage;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class ProjectWorkspaceServiceTests
{
    [Fact]
    public async Task Initialize_and_queries_delegate_to_repository()
    {
        var repository = new FakeProjectRepository();
        var project = CreateProject();
        var device = CreateDevice(project.Id);
        repository.Projects = new[] { project };
        repository.Devices = new[] { device };
        var service = new ProjectWorkspaceService(repository, new FakeCredentialVault());

        await service.InitializeAsync();
        var projects = await service.GetProjectsAsync();
        var devices = await service.GetDevicesAsync(project.Id);

        Assert.True(repository.InitializeCalled);
        Assert.Same(repository.Projects, projects);
        Assert.Same(repository.Devices, devices);
        Assert.Equal(project.Id, repository.RequestedProjectId);
    }

    [Fact]
    public async Task Create_project_validates_then_delegates_to_repository()
    {
        var repository = new FakeProjectRepository();
        var service = new ProjectWorkspaceService(repository, new FakeCredentialVault());

        var projectId = await service.CreateProjectAsync("客户甲", "测评项目", @"C:\Evidence");

        Assert.Equal(repository.ProjectIdToReturn, projectId);
        Assert.Equal("客户甲", repository.CustomerName);
        Assert.Equal("测评项目", repository.ProjectName);
        Assert.Equal(@"C:\Evidence", repository.EvidenceRoot);
    }

    [Theory]
    [InlineData("", "项目", "C:\\Evidence", "请输入客户名称")]
    [InlineData("客户", " ", "C:\\Evidence", "请输入项目名称")]
    [InlineData("客户", "项目", "relative", "请选择完整的 Windows 证据目录")]
    public async Task Create_project_rejects_invalid_input_with_actionable_chinese_message(
        string customerName,
        string projectName,
        string evidenceRoot,
        string expectedMessage)
    {
        var repository = new FakeProjectRepository();
        var service = new ProjectWorkspaceService(repository, new FakeCredentialVault());

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            service.CreateProjectAsync(customerName, projectName, evidenceRoot));

        Assert.Contains(expectedMessage, error.Message, StringComparison.Ordinal);
        Assert.Null(repository.CustomerName);
    }

    [Theory]
    [InlineData("客户\n伪造", "项目", "C:\\Evidence")]
    [InlineData("客户", "项目\r伪造", "C:\\Evidence")]
    [InlineData("客户", "项目", "C:\\Evidence\n伪造")]
    public async Task Create_project_rejects_control_characters(
        string customerName,
        string projectName,
        string evidenceRoot)
    {
        var repository = new FakeProjectRepository();
        var service = new ProjectWorkspaceService(repository, new FakeCredentialVault());

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.CreateProjectAsync(customerName, projectName, evidenceRoot));

        Assert.Null(repository.CustomerName);
    }

    [Fact]
    public async Task Add_device_stores_secret_before_repository_and_clears_original_buffer()
    {
        var calls = new List<string>();
        var repository = new FakeProjectRepository(calls);
        var vault = new FakeCredentialVault(calls);
        var service = new ProjectWorkspaceService(repository, vault);
        var password = "仅用于测试的口令".ToCharArray();

        var deviceId = await service.AddDeviceAsync(
            ProjectId.New(), "核心交换机", "192.0.2.10", 22, password);

        Assert.Equal(repository.DeviceIdToReturn, deviceId);
        Assert.Equal(new[] { "vault.store", "repository.add" }, calls);
        Assert.Equal("仅用于测试的口令", vault.StoredSecretSnapshot);
        Assert.All(password, character => Assert.Equal('\0', character));
        Assert.Equal(vault.ReferenceToReturn, repository.CredentialReference);
        Assert.DoesNotContain("仅用于测试的口令", deviceId.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Add_device_deletes_stored_credential_when_repository_write_fails()
    {
        var calls = new List<string>();
        var repository = new FakeProjectRepository(calls)
        {
            AddDeviceError = new InvalidOperationException("database unavailable")
        };
        var vault = new FakeCredentialVault(calls);
        var service = new ProjectWorkspaceService(repository, vault);
        var password = "失败时也必须清零".ToCharArray();

        var error = await Assert.ThrowsAsync<ProjectWorkspaceException>(() => service.AddDeviceAsync(
            ProjectId.New(), "设备甲", "server.example", 22, password));

        Assert.DoesNotContain("database unavailable", error.Message, StringComparison.Ordinal);
        Assert.Contains("设备未保存", error.Message, StringComparison.Ordinal);
        Assert.Equal(new[] { "vault.store", "repository.add", "vault.delete" }, calls);
        Assert.Equal(vault.ReferenceToReturn, vault.DeletedReference);
        Assert.All(password, character => Assert.Equal('\0', character));
    }

    [Fact]
    public async Task Add_device_keeps_credential_when_repository_committed_before_throwing()
    {
        var calls = new List<string>();
        var repository = new FakeProjectRepository(calls)
        {
            AddDeviceError = new InvalidOperationException("commit result unknown"),
            PersistDeviceBeforeThrow = true
        };
        var vault = new FakeCredentialVault(calls);
        var service = new ProjectWorkspaceService(repository, vault);

        var deviceId = await service.AddDeviceAsync(
            ProjectId.New(), "设备甲", "server.example", 22, "安全口令".ToCharArray());

        Assert.Equal(repository.DeviceIdToReturn, deviceId);
        Assert.Equal(new[] { "vault.store", "repository.add" }, calls);
        Assert.Null(vault.DeletedReference);
    }

    [Fact]
    public async Task Add_device_leaves_credential_for_recovery_when_commit_state_cannot_be_verified()
    {
        var calls = new List<string>();
        var repository = new FakeProjectRepository(calls)
        {
            AddDeviceError = new InvalidOperationException("secret database details"),
            GetDevicesError = new InvalidOperationException("secret verification details")
        };
        var vault = new FakeCredentialVault(calls);
        var service = new ProjectWorkspaceService(repository, vault);

        var error = await Assert.ThrowsAsync<ProjectWorkspaceException>(() => service.AddDeviceAsync(
            ProjectId.New(), "设备甲", "server.example", 22, "安全口令".ToCharArray()));

        Assert.Contains("保存结果无法确认", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("secret", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(error.InnerException);
        Assert.Null(vault.DeletedReference);
    }

    [Fact]
    public async Task Add_device_reports_safe_error_when_compensating_delete_fails()
    {
        var repository = new FakeProjectRepository
        {
            AddDeviceError = new InvalidOperationException("secret repository details")
        };
        var vault = new FakeCredentialVault
        {
            DeleteError = new InvalidOperationException("secret vault details")
        };
        var service = new ProjectWorkspaceService(repository, vault);

        var error = await Assert.ThrowsAsync<ProjectWorkspaceException>(() => service.AddDeviceAsync(
            ProjectId.New(), "设备甲", "server.example", 22, "安全口令".ToCharArray()));

        Assert.Contains("临时凭据未能自动清理", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("secret", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(error.InnerException);
    }

    [Fact]
    public async Task Cancellation_after_vault_store_deletes_uncommitted_credential_and_preserves_cancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var calls = new List<string>();
        var vault = new FakeCredentialVault(calls) { AfterStore = cancellation.Cancel };
        var service = new ProjectWorkspaceService(new FakeProjectRepository(calls), vault);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.AddDeviceAsync(
            ProjectId.New(), "设备甲", "server.example", 22, "安全口令".ToCharArray(), cancellation.Token));

        Assert.Equal(new[] { "vault.store", "repository.add", "vault.delete" }, calls);
        Assert.NotNull(vault.DeletedReference);
    }

    [Fact]
    public async Task Add_device_clears_password_when_vault_store_fails()
    {
        var vault = new FakeCredentialVault
        {
            StoreError = new CredentialVaultException(
                CredentialVaultFailure.StorageFailure,
                "凭据保存失败，请检查本机凭据存储后重试。")
        };
        var service = new ProjectWorkspaceService(new FakeProjectRepository(), vault);
        var password = "不能残留".ToCharArray();

        await Assert.ThrowsAsync<CredentialVaultException>(() => service.AddDeviceAsync(
            ProjectId.New(), "设备甲", "server.example", 22, password));

        Assert.All(password, character => Assert.Equal('\0', character));
    }

    [Theory]
    [InlineData("", "host", 22, "请输入设备名称")]
    [InlineData("设备", " ", 22, "请输入设备地址")]
    [InlineData("设备", "host", 0, "请输入 1 到 65535")]
    [InlineData("设备", "host", 65536, "请输入 1 到 65535")]
    public async Task Add_device_rejects_invalid_input_clears_password_and_never_stores_it(
        string displayName,
        string host,
        int port,
        string expectedMessage)
    {
        var vault = new FakeCredentialVault();
        var service = new ProjectWorkspaceService(new FakeProjectRepository(), vault);
        var password = "待清零".ToCharArray();

        var error = await Assert.ThrowsAsync<ArgumentException>(() => service.AddDeviceAsync(
            ProjectId.New(), displayName, host, port, password));

        Assert.Contains(expectedMessage, error.Message, StringComparison.Ordinal);
        Assert.False(vault.StoreCalled);
        Assert.All(password, character => Assert.Equal('\0', character));
    }

    [Fact]
    public async Task Add_device_rejects_empty_password_and_clears_buffer()
    {
        var vault = new FakeCredentialVault();
        var service = new ProjectWorkspaceService(new FakeProjectRepository(), vault);
        var password = Array.Empty<char>();

        var error = await Assert.ThrowsAsync<ArgumentException>(() => service.AddDeviceAsync(
            ProjectId.New(), "设备", "host", 22, password));

        Assert.Contains("请输入连接密码", error.Message, StringComparison.Ordinal);
        Assert.False(vault.StoreCalled);
        Assert.Empty(password);
    }

    [Theory]
    [InlineData("设备\n伪造", "host")]
    [InlineData("设备", "host\r伪造")]
    [InlineData("设备\0伪造", "host")]
    public async Task Add_device_rejects_control_characters_before_storing_secret(
        string displayName,
        string host)
    {
        var vault = new FakeCredentialVault();
        var service = new ProjectWorkspaceService(new FakeProjectRepository(), vault);

        await Assert.ThrowsAsync<ArgumentException>(() => service.AddDeviceAsync(
            ProjectId.New(), displayName, host, 22, "待清零".ToCharArray()));

        Assert.False(vault.StoreCalled);
    }

    [Fact]
    public void Public_contract_accepts_password_only_as_mutable_character_buffer()
    {
        var method = typeof(IProjectWorkspaceService).GetMethod(nameof(IProjectWorkspaceService.AddDeviceAsync));

        Assert.NotNull(method);
        Assert.Contains(method!.GetParameters(), parameter =>
            parameter.Name == "password" && parameter.ParameterType == typeof(char[]));
        Assert.DoesNotContain(method.GetParameters(), parameter =>
            parameter.Name == "password" && parameter.ParameterType == typeof(string));
        Assert.DoesNotContain(typeof(ProjectWorkspaceService).GetFields(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic),
            field => field.FieldType == typeof(char[]) || field.FieldType == typeof(string));
    }

    private static ProjectRecord CreateProject()
    {
        return new ProjectRecord(ProjectId.New(), "客户", "项目", @"C:\Evidence", DateTimeOffset.UtcNow);
    }

    private static DeviceRecord CreateDevice(ProjectId projectId)
    {
        return new DeviceRecord(
            DeviceId.New(), projectId, "设备", "192.0.2.10", 22, CredentialReference.New(), DateTimeOffset.UtcNow);
    }

    private sealed class FakeCredentialVault : ICredentialVault
    {
        private readonly IList<string>? calls;

        public FakeCredentialVault(IList<string>? calls = null)
        {
            this.calls = calls;
        }

        public CredentialReference ReferenceToReturn { get; } = CredentialReference.New();
        public Exception? StoreError { get; set; }
        public Exception? DeleteError { get; set; }
        public Action? AfterStore { get; set; }
        public bool StoreCalled { get; private set; }
        public string? StoredSecretSnapshot { get; private set; }
        public CredentialReference? DeletedReference { get; private set; }

        public CredentialReference Store(char[] secret, CancellationToken cancellationToken = default)
        {
            calls?.Add("vault.store");
            StoreCalled = true;
            StoredSecretSnapshot = new string(secret);
            if (StoreError != null)
            {
                throw StoreError;
            }

            AfterStore?.Invoke();
            return ReferenceToReturn;
        }

        public char[] Retrieve(CredentialReference reference)
        {
            throw new NotSupportedException();
        }

        public void Delete(CredentialReference reference)
        {
            calls?.Add("vault.delete");
            if (DeleteError != null)
            {
                throw DeleteError;
            }

            DeletedReference = reference;
        }
    }

    private sealed class FakeProjectRepository : IProjectRepository
    {
        private readonly IList<string>? calls;

        public FakeProjectRepository(IList<string>? calls = null)
        {
            this.calls = calls;
        }

        public bool InitializeCalled { get; private set; }
        public ProjectId ProjectIdToReturn { get; } = ProjectId.New();
        public DeviceId DeviceIdToReturn { get; } = DeviceId.New();
        public IReadOnlyList<ProjectRecord> Projects { get; set; } = Array.Empty<ProjectRecord>();
        public IReadOnlyList<DeviceRecord> Devices { get; set; } = Array.Empty<DeviceRecord>();
        public ProjectId? RequestedProjectId { get; private set; }
        public string? CustomerName { get; private set; }
        public string? ProjectName { get; private set; }
        public string? EvidenceRoot { get; private set; }
        public CredentialReference? CredentialReference { get; private set; }
        public Exception? AddDeviceError { get; set; }
        public Exception? GetDevicesError { get; set; }
        public bool PersistDeviceBeforeThrow { get; set; }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            InitializeCalled = true;
            return Task.CompletedTask;
        }

        public Task<ProjectId> CreateProjectAsync(
            string customerName,
            string projectName,
            string evidenceRoot,
            CancellationToken cancellationToken = default)
        {
            CustomerName = customerName;
            ProjectName = projectName;
            EvidenceRoot = evidenceRoot;
            return Task.FromResult(ProjectIdToReturn);
        }

        public Task<DeviceId> AddDeviceAsync(
            ProjectId projectId,
            string displayName,
            string host,
            int port,
            CredentialReference credentialReference,
            CancellationToken cancellationToken = default)
        {
            calls?.Add("repository.add");
            CredentialReference = credentialReference;
            if (PersistDeviceBeforeThrow)
            {
                Devices = new[]
                {
                    new DeviceRecord(
                        DeviceIdToReturn,
                        projectId,
                        displayName,
                        host,
                        port,
                        credentialReference,
                        DateTimeOffset.UtcNow)
                };
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (AddDeviceError != null)
            {
                return Task.FromException<DeviceId>(AddDeviceError);
            }

            return Task.FromResult(DeviceIdToReturn);
        }

        public Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Projects);
        }

        public Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            RequestedProjectId = projectId;
            if (GetDevicesError != null)
            {
                return Task.FromException<IReadOnlyList<DeviceRecord>>(GetDevicesError);
            }

            return Task.FromResult(Devices);
        }

        public Task SaveExecutionAsync(ExecutionRecord record, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<ExecutionRecord>> GetExecutionsAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<EvidenceFileRecord>> GetEvidenceFilesAsync(
            ProjectId projectId,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}
