using System;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public interface IDatabaseConfirmationService
{
    Task<DatabaseConfirmationRecord> ConfirmAsync(
        ProjectRecord project,
        DeviceRecord device,
        DatabaseInstanceCandidate candidate,
        CancellationToken cancellationToken = default);
}

public sealed class DatabaseConfirmationService : IDatabaseConfirmationService
{
    private const string ManualConfirmationSource = "测评人员在数据库候选界面人工确认";
    private readonly IDatabaseConfirmationRepository repository;

    public DatabaseConfirmationService(IDatabaseConfirmationRepository repository)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
    }

    public async Task<DatabaseConfirmationRecord> ConfirmAsync(
        ProjectRecord project,
        DeviceRecord device,
        DatabaseInstanceCandidate candidate,
        CancellationToken cancellationToken = default)
    {
        if (project == null)
        {
            throw new ArgumentNullException(nameof(project));
        }

        if (device == null)
        {
            throw new ArgumentNullException(nameof(device));
        }

        if (candidate == null)
        {
            throw new ArgumentNullException(nameof(candidate));
        }

        if (!device.ProjectId.Equals(project.Id))
        {
            throw new InvalidOperationException("数据库确认设备不属于当前项目。");
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
            ManualConfirmationSource);
        await repository.SaveDatabaseConfirmationAsync(record, cancellationToken).ConfigureAwait(false);
        return record;
    }
}
