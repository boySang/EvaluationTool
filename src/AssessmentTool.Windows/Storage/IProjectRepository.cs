using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Windows.Storage;

public interface IProjectRepository
{
    Task InitializeAsync(CancellationToken cancellationToken = default);
    Task<ProjectId> CreateProjectAsync(
        string customerName,
        string projectName,
        string evidenceRoot,
        CancellationToken cancellationToken = default);
    Task<DeviceId> AddDeviceAsync(
        ProjectId projectId,
        string displayName,
        string host,
        int port,
        CredentialReference credentialReference,
        CancellationToken cancellationToken = default);
    Task<DeviceId> AddDeviceAsync(
        ProjectId projectId,
        string displayName,
        string host,
        int port,
        string userName,
        TargetCategory category,
        ConnectionProtocol protocol,
        CredentialReference credentialReference,
        CancellationToken cancellationToken = default);
    Task SaveExecutionAsync(ExecutionRecord record, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(ProjectId projectId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ExecutionRecord>> GetExecutionsAsync(ProjectId projectId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<EvidenceFileRecord>> GetEvidenceFilesAsync(ProjectId projectId, CancellationToken cancellationToken = default);
    Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default);
}
