using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Execution;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public interface ICollectionWorkflowService
{
    Task<CollectionWorkflowResult> RunAsync(
        CollectionWorkflowRequest request,
        IProgress<CollectionProgress> progress,
        CancellationToken cancellationToken);
}

public enum CollectionAdapterId
{
    GenericLinux = 1,
    HuaweiVrp = 2,
    H3cComware = 3,
    WindowsServerSsh = 4,
    NginxLinuxSsh = 5
}

public sealed class CollectionAdapterOption
{
    public CollectionAdapterOption(
        CollectionAdapterId id,
        string displayName,
        string scopeNotice)
    {
        Id = id;
        DisplayName = string.IsNullOrWhiteSpace(displayName)
            ? throw new ArgumentException("适配器名称不能为空。", nameof(displayName))
            : displayName;
        ScopeNotice = string.IsNullOrWhiteSpace(scopeNotice)
            ? throw new ArgumentException("适配器范围说明不能为空。", nameof(scopeNotice))
            : scopeNotice;
    }

    public CollectionAdapterId Id { get; }
    public string DisplayName { get; }
    public string ScopeNotice { get; }
}

public sealed class CollectionDeviceSelection
{
    public CollectionDeviceSelection(
        DeviceRecord device,
        bool isRequiredComponentAvailable,
        HostKeyTrust hostKeyTrust)
    {
        Device = device ?? throw new ArgumentNullException(nameof(device));
        HostKeyTrust = hostKeyTrust ?? throw new ArgumentNullException(nameof(hostKeyTrust));
        var deviceEndpoint = new SshEndpointIdentity(device.Host, device.Port);
        if (!deviceEndpoint.Equals(hostKeyTrust.Endpoint))
        {
            throw new ArgumentException("SSH 主机指纹信任与所选设备端点不一致。", nameof(hostKeyTrust));
        }

        IsRequiredComponentAvailable = isRequiredComponentAvailable;
    }

    public DeviceRecord Device { get; }
    public bool IsRequiredComponentAvailable { get; }
    public HostKeyTrust HostKeyTrust { get; }

    public bool IsHostKeyTrusted => HostKeyTrust.IsEligibleForAutomaticConnection;
}

public sealed class CollectionWorkflowRequest
{
    public CollectionWorkflowRequest(
        ProjectRecord project,
        CollectionDeviceSelection deviceSelection,
        DetectionCandidate? confirmedCandidate = null,
        Guid? pendingIdentificationBatchId = null)
        : this(
            project,
            deviceSelection,
            CollectionAdapterId.GenericLinux,
            confirmedCandidate,
            pendingIdentificationBatchId)
    {
    }

    public CollectionWorkflowRequest(
        ProjectRecord project,
        CollectionDeviceSelection deviceSelection,
        CollectionAdapterId adapterId,
        DetectionCandidate? confirmedCandidate = null,
        Guid? pendingIdentificationBatchId = null)
    {
        Project = project ?? throw new ArgumentNullException(nameof(project));
        DeviceSelection = deviceSelection ?? throw new ArgumentNullException(nameof(deviceSelection));
        if (!deviceSelection.Device.ProjectId.Equals(project.Id))
        {
            throw new ArgumentException("所选设备不属于当前项目。", nameof(deviceSelection));
        }

        if ((confirmedCandidate == null && pendingIdentificationBatchId.HasValue)
            || (confirmedCandidate != null && !pendingIdentificationBatchId.HasValue))
        {
            throw new ArgumentException("人工确认候选和待确认识别批次必须同时提供。");
        }

        if (pendingIdentificationBatchId == Guid.Empty)
        {
            throw new ArgumentException("待确认识别批次标识不能为空。", nameof(pendingIdentificationBatchId));
        }

        ConfirmedCandidate = confirmedCandidate;
        PendingIdentificationBatchId = pendingIdentificationBatchId;
        AdapterId = adapterId;
    }

    public ProjectRecord Project { get; }
    public CollectionDeviceSelection DeviceSelection { get; }
    public CollectionAdapterId AdapterId { get; }
    public DetectionCandidate? ConfirmedCandidate { get; }
    public Guid? PendingIdentificationBatchId { get; }
}

public enum CollectionWorkflowOutcome
{
    Completed,
    RequiresConfirmation,
    RequiresDatabaseConfirmation,
    Failed,
    Stopped,
    RequiresHostSoftwareConfirmation
}

public sealed class CompletedCollectionCommand
{
    public CompletedCollectionCommand(string commandId)
    {
        CommandId = string.IsNullOrWhiteSpace(commandId)
            ? throw new ArgumentException("命令标识不能为空。", nameof(commandId))
            : commandId;
    }

    public string CommandId { get; }
}

public sealed class CollectionError
{
    private static readonly Regex SensitiveValue = new Regex(
        @"(?<key>password|passwd|pwd|token|secret)\s*[:=]\s*(?<value>[^\s;|]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    public CollectionError(
        string summary,
        string possibleCause,
        string recommendedAction,
        string technicalDetails)
    {
        Summary = Required(summary, nameof(summary));
        PossibleCause = Required(possibleCause, nameof(possibleCause));
        RecommendedAction = Required(recommendedAction, nameof(recommendedAction));
        TechnicalDetails = Required(technicalDetails, nameof(technicalDetails));
    }

    public string Summary { get; }
    public string PossibleCause { get; }
    public string RecommendedAction { get; }
    public string TechnicalDetails { get; }

    internal CollectionError Redacted()
    {
        return new CollectionError(
            Redact(Summary),
            Redact(PossibleCause),
            Redact(RecommendedAction),
            Redact(TechnicalDetails));
    }

    private static string Redact(string value)
    {
        return SensitiveValue.Replace(value, "${key}=***");
    }

    private static string Required(string value, string parameterName)
    {
        return string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("错误信息不能为空。", parameterName)
            : value;
    }
}

public sealed class CollectionWorkflowResult
{
    private CollectionWorkflowResult(
        CollectionWorkflowOutcome outcome,
        IEnumerable<DetectionCandidate> detectionCandidates,
        IEnumerable<DatabaseInstanceCandidate> databaseCandidates,
        IEnumerable<MiddlewareInstanceCandidate> middlewareCandidates,
        IEnumerable<HostSoftwareDiscoveryCandidateRecord> hostSoftwareCandidates,
        IEnumerable<CompletedCollectionCommand> completedCommands,
        CollectionError? error,
        Guid? pendingIdentificationBatchId,
        Guid? pendingHostSoftwareBatchId)
    {
        Outcome = outcome;
        DetectionCandidates = Copy(detectionCandidates, nameof(detectionCandidates));
        DatabaseCandidates = Copy(databaseCandidates, nameof(databaseCandidates));
        MiddlewareCandidates = Copy(middlewareCandidates, nameof(middlewareCandidates));
        HostSoftwareCandidates = Copy(hostSoftwareCandidates, nameof(hostSoftwareCandidates));
        CompletedCommands = Copy(completedCommands, nameof(completedCommands));
        Error = error;
        PendingIdentificationBatchId = pendingIdentificationBatchId;
        PendingHostSoftwareBatchId = pendingHostSoftwareBatchId;
    }

    public CollectionWorkflowOutcome Outcome { get; }
    public IReadOnlyList<DetectionCandidate> DetectionCandidates { get; }
    public IReadOnlyList<DatabaseInstanceCandidate> DatabaseCandidates { get; }
    public IReadOnlyList<MiddlewareInstanceCandidate> MiddlewareCandidates { get; }
    public IReadOnlyList<HostSoftwareDiscoveryCandidateRecord> HostSoftwareCandidates { get; }
    public IReadOnlyList<CompletedCollectionCommand> CompletedCommands { get; }
    public CollectionError? Error { get; }
    public Guid? PendingIdentificationBatchId { get; }
    public Guid? PendingHostSoftwareBatchId { get; }

    public static CollectionWorkflowResult Completed(IEnumerable<CompletedCollectionCommand> completedCommands)
    {
        return new CollectionWorkflowResult(
            CollectionWorkflowOutcome.Completed,
            Array.Empty<DetectionCandidate>(),
            Array.Empty<DatabaseInstanceCandidate>(),
            Array.Empty<MiddlewareInstanceCandidate>(),
            Array.Empty<HostSoftwareDiscoveryCandidateRecord>(),
            completedCommands,
            null,
            null,
            null);
    }

    public static CollectionWorkflowResult RequiresConfirmation(
        IEnumerable<DetectionCandidate> candidates,
        Guid pendingIdentificationBatchId)
    {
        var copied = Copy(candidates, nameof(candidates));
        if (copied.Count == 0)
        {
            throw new ArgumentException("需要确认时必须提供识别候选项。", nameof(candidates));
        }

        if (pendingIdentificationBatchId == Guid.Empty)
        {
            throw new ArgumentException("待确认识别批次标识不能为空。", nameof(pendingIdentificationBatchId));
        }

        return new CollectionWorkflowResult(
            CollectionWorkflowOutcome.RequiresConfirmation,
            copied,
            Array.Empty<DatabaseInstanceCandidate>(),
            Array.Empty<MiddlewareInstanceCandidate>(),
            Array.Empty<HostSoftwareDiscoveryCandidateRecord>(),
            Array.Empty<CompletedCollectionCommand>(),
            null,
            pendingIdentificationBatchId,
            null);
    }

    public static CollectionWorkflowResult RequiresDatabaseConfirmation(
        IEnumerable<DatabaseInstanceCandidate> candidates,
        IEnumerable<CompletedCollectionCommand>? completedCommands = null)
    {
        var copied = Copy(candidates, nameof(candidates));
        if (copied.Count == 0 || copied.All(candidate => !candidate.RequiresUserConfirmation))
        {
            throw new ArgumentException("数据库确认结果必须包含需要人工确认的候选项。", nameof(candidates));
        }

        return new CollectionWorkflowResult(
            CollectionWorkflowOutcome.RequiresDatabaseConfirmation,
            Array.Empty<DetectionCandidate>(),
            copied,
            Array.Empty<MiddlewareInstanceCandidate>(),
            Array.Empty<HostSoftwareDiscoveryCandidateRecord>(),
            completedCommands ?? Array.Empty<CompletedCollectionCommand>(),
            null,
            null,
            null);
    }

    public static CollectionWorkflowResult RequiresHostSoftwareConfirmation(
        IEnumerable<DatabaseInstanceCandidate> databaseCandidates,
        IEnumerable<MiddlewareInstanceCandidate> middlewareCandidates,
        HostSoftwareDiscoveryBatchRecord pendingHostSoftwareBatch,
        IEnumerable<CompletedCollectionCommand>? completedCommands = null)
    {
        var copiedDatabases = Copy(databaseCandidates, nameof(databaseCandidates));
        var copiedMiddleware = Copy(middlewareCandidates, nameof(middlewareCandidates));
        if (pendingHostSoftwareBatch == null)
        {
            throw new ArgumentNullException(nameof(pendingHostSoftwareBatch));
        }

        var copiedHostSoftware = Copy(
            pendingHostSoftwareBatch.Candidates,
            nameof(pendingHostSoftwareBatch));
        if (copiedDatabases.Any(candidate => !candidate.RequiresUserConfirmation))
        {
            throw new ArgumentException("数据库候选项必须先标记为需要人工确认。", nameof(databaseCandidates));
        }

        if (copiedHostSoftware.Count == 0)
        {
            throw new ArgumentException("待确认主机软件批次必须包含候选项。", nameof(pendingHostSoftwareBatch));
        }

        return new CollectionWorkflowResult(
            CollectionWorkflowOutcome.RequiresHostSoftwareConfirmation,
            Array.Empty<DetectionCandidate>(),
            copiedDatabases,
            copiedMiddleware,
            copiedHostSoftware,
            completedCommands ?? Array.Empty<CompletedCollectionCommand>(),
            null,
            null,
            pendingHostSoftwareBatch.BatchId);
    }

    public static CollectionWorkflowResult Failed(CollectionError error)
    {
        return new CollectionWorkflowResult(
            CollectionWorkflowOutcome.Failed,
            Array.Empty<DetectionCandidate>(),
            Array.Empty<DatabaseInstanceCandidate>(),
            Array.Empty<MiddlewareInstanceCandidate>(),
            Array.Empty<HostSoftwareDiscoveryCandidateRecord>(),
            Array.Empty<CompletedCollectionCommand>(),
            error ?? throw new ArgumentNullException(nameof(error)),
            null,
            null);
    }

    public static CollectionWorkflowResult Stopped()
    {
        return new CollectionWorkflowResult(
            CollectionWorkflowOutcome.Stopped,
            Array.Empty<DetectionCandidate>(),
            Array.Empty<DatabaseInstanceCandidate>(),
            Array.Empty<MiddlewareInstanceCandidate>(),
            Array.Empty<HostSoftwareDiscoveryCandidateRecord>(),
            Array.Empty<CompletedCollectionCommand>(),
            null,
            null,
            null);
    }

    private static IReadOnlyList<T> Copy<T>(IEnumerable<T> items, string parameterName)
        where T : class
    {
        if (items == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        var copied = items.ToArray();
        if (copied.Any(item => item == null))
        {
            throw new ArgumentException("集合不能包含空项。", parameterName);
        }

        return new ReadOnlyCollection<T>(copied);
    }
}
