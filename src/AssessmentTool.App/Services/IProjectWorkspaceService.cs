using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.App.Services;

public enum ProjectWorkspaceFailure
{
    DeviceNotSaved,
    DeviceSaveResultUnknown,
    CredentialCleanupFailed
}

public sealed class ProjectWorkspaceException : System.Exception
{
    public ProjectWorkspaceException(ProjectWorkspaceFailure failure, string message)
        : base(message)
    {
        Failure = failure;
    }

    public ProjectWorkspaceFailure Failure { get; }
}

public interface IProjectWorkspaceService
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default);

    Task<ProjectId> CreateProjectAsync(
        string customerName,
        string projectName,
        string evidenceRoot,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default);

    Task<DeviceId> AddDeviceAsync(
        ProjectId projectId,
        string displayName,
        string host,
        int port,
        char[] password,
        CancellationToken cancellationToken = default);

    Task<DeviceId> AddSshDeviceAsync(
        ProjectId projectId,
        string displayName,
        string host,
        int port,
        string userName,
        TargetCategory category,
        char[] password,
        CancellationToken cancellationToken = default);

    Task<DeviceId> AddSshPrivateKeyDeviceAsync(
        ProjectId projectId,
        string displayName,
        string host,
        int port,
        string userName,
        TargetCategory category,
        char[] privateKeyMaterial,
        CancellationToken cancellationToken = default);
}
