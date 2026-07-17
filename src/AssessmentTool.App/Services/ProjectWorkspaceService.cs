using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public sealed class ProjectWorkspaceService : IProjectWorkspaceService
{
    private readonly IProjectRepository repository;
    private readonly ICredentialVault credentialVault;

    public ProjectWorkspaceService(IProjectRepository repository, ICredentialVault credentialVault)
    {
        this.repository = repository
            ?? throw new ArgumentNullException(nameof(repository), "项目数据服务不可用，请重新启动软件后重试。");
        this.credentialVault = credentialVault
            ?? throw new ArgumentNullException(nameof(credentialVault), "凭据保护服务不可用，请重新启动软件后重试。");
    }

    public Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        return repository.InitializeAsync(cancellationToken);
    }

    public Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default)
    {
        return repository.GetProjectsAsync(cancellationToken);
    }

    public Task<ProjectId> CreateProjectAsync(
        string customerName,
        string projectName,
        string evidenceRoot,
        CancellationToken cancellationToken = default)
    {
        ValidateSafeText(customerName, nameof(customerName), "客户名称", 200);
        ValidateSafeText(projectName, nameof(projectName), "项目名称", 200);
        ValidateEvidenceRoot(evidenceRoot);

        return repository.CreateProjectAsync(
            customerName.Trim(),
            projectName.Trim(),
            evidenceRoot.Trim(),
            cancellationToken);
    }

    public Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default)
    {
        ValidateProjectId(projectId);
        return repository.GetDevicesAsync(projectId, cancellationToken);
    }

    public async Task<DeviceId> AddDeviceAsync(
        ProjectId projectId,
        string displayName,
        string host,
        int port,
        char[] password,
        CancellationToken cancellationToken = default)
    {
        return await AddSshDeviceAsync(
            projectId,
            displayName,
            host,
            port,
            "未设置",
            TargetCategory.Automatic,
            password,
            cancellationToken).ConfigureAwait(false);
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
        try
        {
            ValidateProjectId(projectId);
            ValidateSafeText(displayName, nameof(displayName), "设备名称", 128);
            ValidateSafeText(host, nameof(host), "设备地址", 255);
            ValidateSafeText(userName, nameof(userName), "SSH 用户名", 128);
            if (!Enum.IsDefined(typeof(TargetCategory), category))
            {
                throw new ArgumentOutOfRangeException(nameof(category), category, "请选择有效的设备类别后重试。");
            }
            if (port < 1 || port > 65535)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(port), port, "请输入 1 到 65535 之间的连接端口后重试。");
            }

            var endpoint = new SshEndpointIdentity(host.Trim(), port);

            if (password == null || password.Length == 0)
            {
                throw new ArgumentException("请输入连接密码后重试。", nameof(password));
            }

            cancellationToken.ThrowIfCancellationRequested();
            var credentialReference = credentialVault.Store(password, cancellationToken);
            try
            {
                return await repository.AddDeviceAsync(
                    projectId,
                    displayName.Trim(),
                    endpoint.Host,
                    endpoint.Port,
                    userName.Trim(),
                    category,
                    ConnectionProtocol.Ssh,
                    credentialReference,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception repositoryError)
            {
                IReadOnlyList<DeviceRecord> devices;
                try
                {
                    devices = await repository.GetDevicesAsync(projectId, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    throw new ProjectWorkspaceException(
                        ProjectWorkspaceFailure.DeviceSaveResultUnknown,
                        "设备保存结果无法确认。为避免破坏可能已保存的设备，凭据已保留；请重新启动软件并检查设备列表。若设备不存在，请联系管理员清理未使用凭据。");
                }

                var persisted = FindByCredentialReference(devices, credentialReference);
                if (persisted != null)
                {
                    return persisted.Id;
                }

                try
                {
                    credentialVault.Delete(credentialReference);
                }
                catch (Exception)
                {
                    throw new ProjectWorkspaceException(
                        ProjectWorkspaceFailure.CredentialCleanupFailed,
                        "设备未保存，且临时凭据未能自动清理。请关闭软件并联系管理员检查本机凭据目录。");
                }

                if (repositoryError is OperationCanceledException && cancellationToken.IsCancellationRequested)
                {
                    throw new OperationCanceledException(cancellationToken);
                }

                throw new ProjectWorkspaceException(
                    ProjectWorkspaceFailure.DeviceNotSaved,
                    "设备未保存。临时凭据已安全清理，请检查项目数据库后重试。");
            }
        }
        finally
        {
            if (password != null)
            {
                Array.Clear(password, 0, password.Length);
            }
        }
    }

    private static void ValidateProjectId(ProjectId projectId)
    {
        if (projectId.Equals(default(ProjectId)))
        {
            throw new ArgumentException("请先选择有效项目后重试。", nameof(projectId));
        }
    }

    private static void ValidateRequiredText(string value, string parameterName, string message)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(message, parameterName);
        }
    }

    private static void ValidateSafeText(
        string value,
        string parameterName,
        string displayName,
        int maximumLength)
    {
        ValidateRequiredText(value, parameterName, "请输入" + displayName + "后重试。");
        var trimmed = value.Trim();
        if (trimmed.Length > maximumLength || trimmed.Any(char.IsControl))
        {
            throw new ArgumentException(
                displayName + "包含控制字符或长度超过 " + maximumLength + " 个字符。",
                parameterName);
        }
    }

    private static DeviceRecord? FindByCredentialReference(
        IEnumerable<DeviceRecord> devices,
        CredentialReference credentialReference)
    {
        foreach (var device in devices)
        {
            if (device != null && device.CredentialReference.Equals(credentialReference))
            {
                return device;
            }
        }

        return null;
    }

    private static void ValidateEvidenceRoot(string evidenceRoot)
    {
        try
        {
            WindowsEvidenceRootPolicy.Normalize(evidenceRoot, nameof(evidenceRoot));
        }
        catch (ArgumentException)
        {
            throw new ArgumentException(
                "请选择完整的 Windows 证据目录，例如 C:\\测评证据 或 \\\\服务器\\共享目录。",
                nameof(evidenceRoot));
        }
    }
}
