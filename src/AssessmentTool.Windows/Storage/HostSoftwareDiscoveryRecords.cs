using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Windows.Storage;

public enum HostSoftwareCategory
{
    Database = 1,
    Middleware = 2
}

public enum HostSoftwareInstallationType
{
    LocalService = 0,
    Container = 1
}

public enum HostSoftwareEvidenceKind
{
    Service = 1,
    Process = 2,
    Package = 3,
    Container = 4,
    ListeningEndpoint = 5,
    CommandOutput = 6
}

public enum HostSoftwareCandidateDecision
{
    Confirmed = 1,
    Rejected = 2
}

public sealed class HostSoftwareDiscoveryEvidenceInput
{
    public HostSoftwareDiscoveryEvidenceInput(
        HostSoftwareEvidenceKind kind,
        string sourceCommandId,
        string excerpt,
        string rawOutputSha256)
    {
        Kind = RequireEnum(kind, nameof(kind));
        SourceCommandId = RequireText(sourceCommandId, nameof(sourceCommandId));
        Excerpt = RequireText(excerpt, nameof(excerpt));
        RawOutputSha256 = PublishedCommandPackRecord.RequireSha256(rawOutputSha256, nameof(rawOutputSha256));
    }

    public HostSoftwareEvidenceKind Kind { get; }
    public string SourceCommandId { get; }
    public string Excerpt { get; }
    public string RawOutputSha256 { get; }

    internal static TEnum RequireEnum<TEnum>(TEnum value, string parameterName)
        where TEnum : struct
    {
        if (!Enum.IsDefined(typeof(TEnum), value))
        {
            throw new ArgumentOutOfRangeException(parameterName, value, "Stored discovery enum value is invalid.");
        }

        return value;
    }

    internal static string RequireText(string value, string parameterName)
    {
        var normalized = PublishedCommandPackRecord.RequireText(value, parameterName);
        if (normalized.Any(char.IsControl))
        {
            throw new ArgumentException("Value cannot contain control characters.", parameterName);
        }

        return normalized;
    }
}

public sealed class HostSoftwareDiscoveryCandidateInput
{
    public HostSoftwareDiscoveryCandidateInput(
        HostSoftwareCategory category,
        string product,
        string? version,
        HostSoftwareInstallationType installationType,
        string instanceName,
        string? portEvidence,
        double confidence,
        IReadOnlyList<HostSoftwareDiscoveryEvidenceInput> sources)
    {
        Category = HostSoftwareDiscoveryEvidenceInput.RequireEnum(category, nameof(category));
        Product = HostSoftwareDiscoveryEvidenceInput.RequireText(product, nameof(product));
        Version = OptionalText(version, nameof(version));
        InstallationType = HostSoftwareDiscoveryEvidenceInput.RequireEnum(installationType, nameof(installationType));
        InstanceName = HostSoftwareDiscoveryEvidenceInput.RequireText(instanceName, nameof(instanceName));
        PortEvidence = OptionalText(portEvidence, nameof(portEvidence));
        if (double.IsNaN(confidence) || double.IsInfinity(confidence) || confidence < 0 || confidence > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(confidence), confidence, "Discovery confidence must be between zero and one.");
        }

        if (sources == null)
        {
            throw new ArgumentNullException(nameof(sources));
        }

        var copiedSources = sources.ToArray();
        if (copiedSources.Length == 0 || copiedSources.Length > 64 || copiedSources.Any(source => source == null))
        {
            throw new ArgumentException("Each discovery candidate must contain 1 to 64 complete evidence sources.", nameof(sources));
        }

        Confidence = confidence;
        Sources = new ReadOnlyCollection<HostSoftwareDiscoveryEvidenceInput>(copiedSources);
    }

    public HostSoftwareCategory Category { get; }
    public string Product { get; }
    public string? Version { get; }
    public HostSoftwareInstallationType InstallationType { get; }
    public string InstanceName { get; }
    public string? PortEvidence { get; }
    public double Confidence { get; }
    public IReadOnlyList<HostSoftwareDiscoveryEvidenceInput> Sources { get; }
    public bool RequiresUserConfirmation => true;

    private static string? OptionalText(string? value, string parameterName)
    {
        return value == null ? null : HostSoftwareDiscoveryEvidenceInput.RequireText(value, parameterName);
    }
}

public sealed class HostSoftwareDiscoveryEvidenceRecord
{
    public HostSoftwareDiscoveryEvidenceRecord(
        Guid evidenceId,
        Guid candidateId,
        int ordinal,
        CollectionTaskId collectionTaskId,
        int commandOrdinal,
        HostSoftwareEvidenceKind kind,
        string sourceCommandId,
        string excerpt,
        string rawOutputSha256)
    {
        EvidenceId = RequireId(evidenceId, nameof(evidenceId));
        CandidateId = RequireId(candidateId, nameof(candidateId));
        if (ordinal < 0 || ordinal >= 64)
        {
            throw new ArgumentOutOfRangeException(nameof(ordinal));
        }

        Ordinal = ordinal;
        if (collectionTaskId.Equals(default(CollectionTaskId)))
        {
            throw new ArgumentException("Collection task ID must be initialized.", nameof(collectionTaskId));
        }

        if (commandOrdinal < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(commandOrdinal));
        }

        CollectionTaskId = collectionTaskId;
        CommandOrdinal = commandOrdinal;
        Kind = HostSoftwareDiscoveryEvidenceInput.RequireEnum(kind, nameof(kind));
        SourceCommandId = HostSoftwareDiscoveryEvidenceInput.RequireText(sourceCommandId, nameof(sourceCommandId));
        Excerpt = HostSoftwareDiscoveryEvidenceInput.RequireText(excerpt, nameof(excerpt));
        RawOutputSha256 = PublishedCommandPackRecord.RequireSha256(rawOutputSha256, nameof(rawOutputSha256));
    }

    public Guid EvidenceId { get; }
    public Guid CandidateId { get; }
    public int Ordinal { get; }
    public CollectionTaskId CollectionTaskId { get; }
    public int CommandOrdinal { get; }
    public HostSoftwareEvidenceKind Kind { get; }
    public string SourceCommandId { get; }
    public string Excerpt { get; }
    public string RawOutputSha256 { get; }

    internal static Guid RequireId(Guid value, string parameterName)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("Identifier cannot be empty.", parameterName);
        }

        return value;
    }
}

public sealed class HostSoftwareDiscoveryCandidateRecord
{
    public HostSoftwareDiscoveryCandidateRecord(
        Guid candidateId,
        Guid batchId,
        int ordinal,
        HostSoftwareCategory category,
        string product,
        string? version,
        HostSoftwareInstallationType installationType,
        string instanceName,
        string? portEvidence,
        double confidence,
        IReadOnlyList<HostSoftwareDiscoveryEvidenceRecord> sources)
    {
        CandidateId = HostSoftwareDiscoveryEvidenceRecord.RequireId(candidateId, nameof(candidateId));
        BatchId = HostSoftwareDiscoveryEvidenceRecord.RequireId(batchId, nameof(batchId));
        if (ordinal < 0 || ordinal >= 64)
        {
            throw new ArgumentOutOfRangeException(nameof(ordinal));
        }

        var copiedSources = (sources ?? throw new ArgumentNullException(nameof(sources))).ToArray();
        if (copiedSources.Any(source => source == null))
        {
            throw new ArgumentException("Evidence sources cannot contain null items.", nameof(sources));
        }

        var input = new HostSoftwareDiscoveryCandidateInput(
            category,
            product,
            version,
            installationType,
            instanceName,
            portEvidence,
            confidence,
            copiedSources
                .Select(source => new HostSoftwareDiscoveryEvidenceInput(
                    source.Kind, source.SourceCommandId, source.Excerpt, source.RawOutputSha256))
                .ToArray());
        if (copiedSources.Any(source => source.CandidateId != candidateId)
            || !copiedSources.Select(source => source.Ordinal).SequenceEqual(
                Enumerable.Range(0, copiedSources.Length))
            || copiedSources.Select(source => source.EvidenceId).Distinct().Count() != copiedSources.Length)
        {
            throw new ArgumentException(
                "Evidence sources must belong to the candidate and use unique contiguous ordinals.",
                nameof(sources));
        }

        Ordinal = ordinal;
        Category = input.Category;
        Product = input.Product;
        Version = input.Version;
        InstallationType = input.InstallationType;
        InstanceName = input.InstanceName;
        PortEvidence = input.PortEvidence;
        Confidence = input.Confidence;
        Sources = new ReadOnlyCollection<HostSoftwareDiscoveryEvidenceRecord>(copiedSources);
    }

    public Guid CandidateId { get; }
    public Guid BatchId { get; }
    public int Ordinal { get; }
    public HostSoftwareCategory Category { get; }
    public string Product { get; }
    public string? Version { get; }
    public HostSoftwareInstallationType InstallationType { get; }
    public string InstanceName { get; }
    public string? PortEvidence { get; }
    public double Confidence { get; }
    public IReadOnlyList<HostSoftwareDiscoveryEvidenceRecord> Sources { get; }
    public bool RequiresUserConfirmation => true;
}

public sealed class HostSoftwareDiscoveryBatchRecord
{
    public HostSoftwareDiscoveryBatchRecord(
        Guid batchId,
        ProjectId projectId,
        DeviceId deviceId,
        CollectionTaskId collectionTaskId,
        long revision,
        Guid? previousBatchId,
        string discoverySource,
        IReadOnlyList<HostSoftwareDiscoveryCandidateRecord> candidates,
        DateTimeOffset recordedAt)
    {
        BatchId = HostSoftwareDiscoveryEvidenceRecord.RequireId(batchId, nameof(batchId));
        if (projectId.Equals(default(ProjectId)))
        {
            throw new ArgumentException("Project ID must be initialized.", nameof(projectId));
        }

        if (deviceId.Equals(default(DeviceId)))
        {
            throw new ArgumentException("Device ID must be initialized.", nameof(deviceId));
        }

        if (collectionTaskId.Equals(default(CollectionTaskId)))
        {
            throw new ArgumentException("Collection task ID must be initialized.", nameof(collectionTaskId));
        }

        if (revision < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(revision));
        }

        if (previousBatchId == Guid.Empty || (revision == 1 && previousBatchId.HasValue)
            || (revision > 1 && !previousBatchId.HasValue))
        {
            throw new ArgumentException("Discovery batch predecessor does not match its revision.", nameof(previousBatchId));
        }

        var copiedCandidates = (candidates ?? throw new ArgumentNullException(nameof(candidates))).ToArray();
        if (copiedCandidates.Length == 0 || copiedCandidates.Length > 64
            || copiedCandidates.Any(candidate => candidate == null || candidate.BatchId != batchId)
            || copiedCandidates.SelectMany(candidate => candidate.Sources)
                .Any(source => !source.CollectionTaskId.Equals(collectionTaskId))
            || !copiedCandidates.Select(candidate => candidate.Ordinal).SequenceEqual(
                Enumerable.Range(0, copiedCandidates.Length))
            || copiedCandidates.Select(candidate => candidate.CandidateId).Distinct().Count()
                != copiedCandidates.Length)
        {
            throw new ArgumentException(
                "Discovery batch must contain 1 to 64 unique candidates with contiguous ordinals.",
                nameof(candidates));
        }

        if (recordedAt == default(DateTimeOffset))
        {
            throw new ArgumentException("Discovery time cannot be empty.", nameof(recordedAt));
        }

        ProjectId = projectId;
        DeviceId = deviceId;
        CollectionTaskId = collectionTaskId;
        Revision = revision;
        PreviousBatchId = previousBatchId;
        DiscoverySource = HostSoftwareDiscoveryEvidenceInput.RequireText(discoverySource, nameof(discoverySource));
        Candidates = new ReadOnlyCollection<HostSoftwareDiscoveryCandidateRecord>(copiedCandidates);
        RecordedAt = recordedAt.ToUniversalTime();
    }

    public Guid BatchId { get; }
    public ProjectId ProjectId { get; }
    public DeviceId DeviceId { get; }
    public CollectionTaskId CollectionTaskId { get; }
    public long Revision { get; }
    public Guid? PreviousBatchId { get; }
    public string DiscoverySource { get; }
    public IReadOnlyList<HostSoftwareDiscoveryCandidateRecord> Candidates { get; }
    public DateTimeOffset RecordedAt { get; }
}

public sealed class HostSoftwareCandidateDecisionRecord
{
    public HostSoftwareCandidateDecisionRecord(
        Guid decisionId,
        Guid candidateId,
        HostSoftwareCandidateDecision decision,
        string decidedBy,
        string decisionSource,
        string? reason,
        DateTimeOffset decidedAt)
    {
        DecisionId = HostSoftwareDiscoveryEvidenceRecord.RequireId(decisionId, nameof(decisionId));
        CandidateId = HostSoftwareDiscoveryEvidenceRecord.RequireId(candidateId, nameof(candidateId));
        Decision = HostSoftwareDiscoveryEvidenceInput.RequireEnum(decision, nameof(decision));
        DecidedBy = HostSoftwareDiscoveryEvidenceInput.RequireText(decidedBy, nameof(decidedBy));
        DecisionSource = HostSoftwareDiscoveryEvidenceInput.RequireText(decisionSource, nameof(decisionSource));
        Reason = reason == null ? null : HostSoftwareDiscoveryEvidenceInput.RequireText(reason, nameof(reason));
        if (decision == HostSoftwareCandidateDecision.Rejected && Reason == null)
        {
            throw new ArgumentException("A rejected candidate must include an audit reason.", nameof(reason));
        }
        if (decidedAt == default(DateTimeOffset))
        {
            throw new ArgumentException("Decision time cannot be empty.", nameof(decidedAt));
        }

        DecidedAt = decidedAt.ToUniversalTime();
    }

    public Guid DecisionId { get; }
    public Guid CandidateId { get; }
    public HostSoftwareCandidateDecision Decision { get; }
    public string DecidedBy { get; }
    public string DecisionSource { get; }
    public string? Reason { get; }
    public DateTimeOffset DecidedAt { get; }
}
