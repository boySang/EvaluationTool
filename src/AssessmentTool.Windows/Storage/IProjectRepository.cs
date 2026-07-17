using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Commands;

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

public interface IDatabaseConfirmationRepository
{
    Task SaveDatabaseConfirmationAsync(
        DatabaseConfirmationRecord record,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<DatabaseConfirmationRecord>> GetDatabaseConfirmationsAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default);
}

public interface ISshHostKeyTrustRepository
{
    Task<SshHostKeyTrustRecord> GetSshHostKeyTrustAsync(
        DeviceId deviceId,
        CancellationToken cancellationToken = default);
    Task<SshHostKeyTrustRecord> SaveSshHostKeyTrustAsync(
        DeviceId deviceId,
        HostKeyTrust trust,
        long expectedRevision,
        CancellationToken cancellationToken = default);
}

public interface ICommandDraftRepository
{
    Task<Guid> SaveCommandDraftAsync(
        CommandDraftImportResult draft,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<CommandDraftArchiveRecord>> GetCommandDraftsAsync(
        CancellationToken cancellationToken = default);
}

public sealed class CommandDraftArchiveRecord
{
    public CommandDraftArchiveRecord(
        Guid id,
        string sourceFileName,
        string rawSha256,
        string rawJson,
        DateTimeOffset importedAt,
        IReadOnlyList<CommandDraftItem> commands,
        IReadOnlyList<CommandDraftFinding> findings)
    {
        Id = id;
        SourceFileName = sourceFileName ?? throw new ArgumentNullException(nameof(sourceFileName));
        RawSha256 = rawSha256 ?? throw new ArgumentNullException(nameof(rawSha256));
        RawJson = rawJson ?? throw new ArgumentNullException(nameof(rawJson));
        ImportedAt = importedAt;
        Commands = new ReadOnlyCollection<CommandDraftItem>(
            (commands ?? throw new ArgumentNullException(nameof(commands))).ToArray());
        Findings = new ReadOnlyCollection<CommandDraftFinding>(
            (findings ?? throw new ArgumentNullException(nameof(findings))).ToArray());
    }

    public Guid Id { get; }
    public string SourceFileName { get; }
    public string RawSha256 { get; }
    public string RawJson { get; }
    public DateTimeOffset ImportedAt { get; }
    public IReadOnlyList<CommandDraftItem> Commands { get; }
    public IReadOnlyList<CommandDraftFinding> Findings { get; }
    public bool IsPendingReview => true;
    public bool IsExecutable => false;
}
