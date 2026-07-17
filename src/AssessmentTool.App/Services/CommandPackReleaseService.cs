using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public interface ICommandPackReleaseService
{
    Task<CommandPackReleaseSnapshot> LoadAsync(
        ProjectId? projectId,
        CancellationToken cancellationToken = default);

    Task<PublishedCommandPackRecord> ReviewAndPublishAsync(
        Guid draftId,
        string reviewedBy,
        CancellationToken cancellationToken = default);

    Task<ProjectCommandPackLockRecord> LockToProjectAsync(
        ProjectId projectId,
        string packId,
        string version,
        string source,
        CancellationToken cancellationToken = default);

    Task<CommandPack?> LoadCurrentProjectPackAsync(
        ProjectId projectId,
        string packId,
        CancellationToken cancellationToken = default);
}

public sealed class CommandPackReleaseSnapshot
{
    public CommandPackReleaseSnapshot(
        IEnumerable<PublishedCommandPackRecord> publishedPacks,
        IEnumerable<ProjectCommandPackLockRecord> currentLocks)
    {
        PublishedPacks = new ReadOnlyCollection<PublishedCommandPackRecord>(
            (publishedPacks ?? throw new ArgumentNullException(nameof(publishedPacks))).ToArray());
        CurrentLocks = new ReadOnlyCollection<ProjectCommandPackLockRecord>(
            (currentLocks ?? throw new ArgumentNullException(nameof(currentLocks))).ToArray());
    }

    public IReadOnlyList<PublishedCommandPackRecord> PublishedPacks { get; }
    public IReadOnlyList<ProjectCommandPackLockRecord> CurrentLocks { get; }
}

public sealed class CommandPackReleaseException : Exception
{
    public CommandPackReleaseException(string message)
        : base(message)
    {
    }

    public CommandPackReleaseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class CommandPackReleaseService : ICommandPackReleaseService
{
    private readonly ICommandDraftRepository draftRepository;
    private readonly ICommandPackPublishingRepository publishingRepository;
    private readonly CommandDraftImporter importer;
    private readonly CommandReleaseReviewer reviewer;

    public CommandPackReleaseService(
        ICommandDraftRepository draftRepository,
        ICommandPackPublishingRepository publishingRepository)
        : this(
            draftRepository,
            publishingRepository,
            new CommandDraftImporter(),
            new CommandReleaseReviewer())
    {
    }

    internal CommandPackReleaseService(
        ICommandDraftRepository draftRepository,
        ICommandPackPublishingRepository publishingRepository,
        CommandDraftImporter importer,
        CommandReleaseReviewer reviewer)
    {
        this.draftRepository = draftRepository ?? throw new ArgumentNullException(nameof(draftRepository));
        this.publishingRepository = publishingRepository ?? throw new ArgumentNullException(nameof(publishingRepository));
        this.importer = importer ?? throw new ArgumentNullException(nameof(importer));
        this.reviewer = reviewer ?? throw new ArgumentNullException(nameof(reviewer));
    }

    public async Task<CommandPackReleaseSnapshot> LoadAsync(
        ProjectId? projectId,
        CancellationToken cancellationToken = default)
    {
        var published = await publishingRepository
            .GetPublishedCommandPacksAsync(cancellationToken)
            .ConfigureAwait(false);
        var locks = projectId.HasValue
            ? await publishingRepository
                .GetCurrentProjectCommandPackLocksAsync(projectId.Value, cancellationToken)
                .ConfigureAwait(false)
            : Array.Empty<ProjectCommandPackLockRecord>();
        return new CommandPackReleaseSnapshot(published, locks);
    }

    public async Task<PublishedCommandPackRecord> ReviewAndPublishAsync(
        Guid draftId,
        string reviewedBy,
        CancellationToken cancellationToken = default)
    {
        if (draftId == Guid.Empty)
        {
            throw new ArgumentException("请选择需要审核的命令草稿。", nameof(draftId));
        }

        if (string.IsNullOrWhiteSpace(reviewedBy))
        {
            throw new CommandPackReleaseException("请填写实际执行审核的人员姓名或工号。");
        }

        var archived = (await draftRepository.GetCommandDraftsAsync(cancellationToken).ConfigureAwait(false))
            .SingleOrDefault(item => item.Id == draftId);
        if (archived == null)
        {
            throw new CommandPackReleaseException("命令草稿不存在或已无法读取，请刷新后重试。");
        }

        var imported = importer.Import(
            new UTF8Encoding(false).GetBytes(archived.RawJson),
            archived.SourceFileName,
            archived.ImportedAt);
        if (!string.Equals(imported.RawSha256, archived.RawSha256, StringComparison.Ordinal))
        {
            throw new CommandPackReleaseException("命令草稿内容完整性校验失败，已阻止发布。");
        }

        var reviewedAt = DateTimeOffset.UtcNow;
        CommandReleaseReviewResult result;
        try
        {
            var request = CommandReleaseReviewRequestFactory.FromImportedMetadata(
                imported,
                reviewedBy.Trim(),
                reviewedAt);
            result = reviewer.Review(imported, request);
        }
        catch (Exception exception) when (!(exception is OperationCanceledException))
        {
            throw new CommandPackReleaseException("命令包审核资料无法解析，已阻止发布。", exception);
        }

        if (!result.IsPublishable || result.Candidate == null)
        {
            var blockers = result.Findings
                .Where(finding => finding.Severity == CommandDraftFindingSeverity.Blocker)
                .Take(5)
                .Select(finding => finding.Message)
                .ToArray();
            throw new CommandPackReleaseException(
                blockers.Length == 0
                    ? "命令包未通过只读安全审核。"
                    : "命令包未通过只读安全审核：" + string.Join("；", blockers));
        }

        var candidate = result.Candidate;
        var published = new PublishedCommandPackRecord(
            candidate.PackId,
            candidate.PackName,
            candidate.PackVersion,
            candidate.OfficialSource,
            candidate.CanonicalSha256,
            candidate.CanonicalJson,
            draftId,
            archived.RawSha256,
            candidate.ReviewedBy,
            candidate.ReviewedAt,
            DateTimeOffset.UtcNow);
        try
        {
            return await publishingRepository
                .PublishCommandPackAsync(published, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (!(exception is OperationCanceledException))
        {
            throw new CommandPackReleaseException(
                "该命令包版本已经发布，或本地不可变发布记录无法写入。请提高版本号后重新审核。",
                exception);
        }
    }

    public async Task<ProjectCommandPackLockRecord> LockToProjectAsync(
        ProjectId projectId,
        string packId,
        string version,
        string source,
        CancellationToken cancellationToken = default)
    {
        var current = await publishingRepository
            .GetCurrentProjectCommandPackLockAsync(projectId, packId, cancellationToken)
            .ConfigureAwait(false);
        if (current != null && string.Equals(current.Version, version, StringComparison.Ordinal))
        {
            return current;
        }

        return await publishingRepository.AppendProjectCommandPackLockAsync(
            projectId,
            packId,
            version,
            current?.Revision ?? 0,
            source,
            DateTimeOffset.UtcNow,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<CommandPack?> LoadCurrentProjectPackAsync(
        ProjectId projectId,
        string packId,
        CancellationToken cancellationToken = default)
    {
        var current = await publishingRepository
            .GetCurrentProjectCommandPackLockAsync(projectId, packId, cancellationToken)
            .ConfigureAwait(false);
        if (current == null)
        {
            return null;
        }

        var published = await publishingRepository
            .GetPublishedCommandPackAsync(current.PackId, current.Version, cancellationToken)
            .ConfigureAwait(false);
        if (published == null)
        {
            throw new InvalidDataException("项目锁定的命令包版本不存在，已阻止执行。");
        }

        return new CommandPackLoader().Load(
            new UTF8Encoding(false, true).GetBytes(published.RawJson),
            published.RawSha256);
    }
}
