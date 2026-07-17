using System;

namespace AssessmentTool.Windows.Storage;

public sealed class PublishedCommandPackRecord
{
    public PublishedCommandPackRecord(
        string packId,
        string packName,
        string version,
        string officialSource,
        string rawSha256,
        string rawJson,
        Guid sourceDraftId,
        string sourceDraftSha256,
        string reviewedBy,
        DateTimeOffset reviewedAt,
        DateTimeOffset publishedAt)
    {
        PackId = RequireText(packId, nameof(packId));
        PackName = RequireText(packName, nameof(packName));
        Version = RequireText(version, nameof(version));
        OfficialSource = RequireText(officialSource, nameof(officialSource));
        RawSha256 = RequireSha256(rawSha256, nameof(rawSha256));
        RawJson = RequireText(rawJson, nameof(rawJson));
        if (sourceDraftId == Guid.Empty)
        {
            throw new ArgumentException("Source draft ID cannot be empty.", nameof(sourceDraftId));
        }

        SourceDraftId = sourceDraftId;
        SourceDraftSha256 = RequireSha256(sourceDraftSha256, nameof(sourceDraftSha256));
        ReviewedBy = RequireText(reviewedBy, nameof(reviewedBy));
        ReviewedAt = reviewedAt.ToUniversalTime();
        PublishedAt = publishedAt.ToUniversalTime();
    }

    public string PackId { get; }
    public string PackName { get; }
    public string Version { get; }
    public string OfficialSource { get; }
    public string RawSha256 { get; }
    public string RawJson { get; }
    public Guid SourceDraftId { get; }
    public string SourceDraftSha256 { get; }
    public string ReviewedBy { get; }
    public DateTimeOffset ReviewedAt { get; }
    public DateTimeOffset PublishedAt { get; }

    internal static string RequireText(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be blank.", parameterName);
        }

        return value.Trim();
    }

    internal static string RequireSha256(string value, string parameterName)
    {
        var normalized = RequireText(value, parameterName).ToLowerInvariant();
        if (normalized.Length != 64)
        {
            throw new ArgumentException("SHA-256 must contain exactly 64 hexadecimal characters.", parameterName);
        }

        for (var index = 0; index < normalized.Length; index++)
        {
            var character = normalized[index];
            if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
            {
                throw new ArgumentException("SHA-256 must contain only hexadecimal characters.", parameterName);
            }
        }

        return normalized;
    }
}

public sealed class ProjectCommandPackLockRecord
{
    public ProjectCommandPackLockRecord(
        Guid id,
        AssessmentTool.Core.Domain.ProjectId projectId,
        string packId,
        string version,
        long revision,
        Guid? previousLockId,
        string lockSource,
        DateTimeOffset lockedAt)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("Lock ID cannot be empty.", nameof(id));
        }

        if (revision < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(revision));
        }

        if (projectId.Equals(default(AssessmentTool.Core.Domain.ProjectId)))
        {
            throw new ArgumentException("Project ID cannot be empty.", nameof(projectId));
        }

        Id = id;
        ProjectId = projectId;
        PackId = PublishedCommandPackRecord.RequireText(packId, nameof(packId));
        Version = PublishedCommandPackRecord.RequireText(version, nameof(version));
        Revision = revision;
        PreviousLockId = previousLockId;
        LockSource = PublishedCommandPackRecord.RequireText(lockSource, nameof(lockSource));
        LockedAt = lockedAt.ToUniversalTime();
    }

    public Guid Id { get; }
    public AssessmentTool.Core.Domain.ProjectId ProjectId { get; }
    public string PackId { get; }
    public string Version { get; }
    public long Revision { get; }
    public Guid? PreviousLockId { get; }
    public string LockSource { get; }
    public DateTimeOffset LockedAt { get; }
}
