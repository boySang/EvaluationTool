using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public enum EvidenceShaStatus
{
    Complete,
    Verified,
    Missing,
    Mismatch,
    UnsafePath,
    Unavailable,
    NotAvailable
}

public enum EvidenceCenterFailure
{
    InvalidProject,
    IndexUnavailable,
    VerificationUnavailable
}

public sealed class EvidenceCenterException : InvalidOperationException
{
    public EvidenceCenterException(EvidenceCenterFailure failure, string message)
        : base(message)
    {
        Failure = failure;
    }

    public EvidenceCenterFailure Failure { get; }
}

public sealed class EvidenceCenterItem
{
    public EvidenceCenterItem(
        string deviceId,
        string commandId,
        string commandText,
        DateTimeOffset startedAt,
        DateTimeOffset? completedAt,
        ExecutionStatus executionStatus,
        string? rawOutputPath,
        int screenshotCount,
        EvidenceShaStatus shaStatus)
        : this(
            deviceId,
            deviceId,
            commandId,
            commandText,
            startedAt,
            completedAt,
            executionStatus,
            rawOutputPath,
            screenshotCount,
            shaStatus)
    {
    }

    public EvidenceCenterItem(
        string deviceId,
        string deviceName,
        string commandId,
        string commandText,
        DateTimeOffset startedAt,
        DateTimeOffset? completedAt,
        ExecutionStatus executionStatus,
        string? rawOutputPath,
        int screenshotCount,
        EvidenceShaStatus shaStatus)
        : this(
            deviceId,
            deviceName,
            commandId,
            commandText,
            startedAt,
            completedAt,
            executionStatus,
            rawOutputPath,
            Array.Empty<string>(),
            screenshotCount,
            shaStatus)
    {
    }

    public EvidenceCenterItem(
        string deviceId,
        string deviceName,
        string commandId,
        string commandText,
        DateTimeOffset startedAt,
        DateTimeOffset? completedAt,
        ExecutionStatus executionStatus,
        string? rawOutputPath,
        IEnumerable<string> evidenceImagePaths,
        int screenshotCount,
        EvidenceShaStatus shaStatus)
    {
        DeviceId = deviceId ?? throw new ArgumentNullException(nameof(deviceId));
        DeviceName = string.IsNullOrWhiteSpace(deviceName)
            ? throw new ArgumentException("设备名称不能为空。", nameof(deviceName))
            : deviceName;
        CommandId = commandId ?? throw new ArgumentNullException(nameof(commandId));
        CommandText = commandText ?? throw new ArgumentNullException(nameof(commandText));
        if (!Enum.IsDefined(typeof(ExecutionStatus), executionStatus))
        {
            throw new ArgumentOutOfRangeException(nameof(executionStatus));
        }

        if (screenshotCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(screenshotCount));
        }

        if (!Enum.IsDefined(typeof(EvidenceShaStatus), shaStatus))
        {
            throw new ArgumentOutOfRangeException(nameof(shaStatus));
        }

        if (evidenceImagePaths == null)
        {
            throw new ArgumentNullException(nameof(evidenceImagePaths));
        }

        var normalizedImagePaths = evidenceImagePaths
            .Select(path => WindowsEvidenceRelativePathPolicy.Normalize(path, nameof(evidenceImagePaths)))
            .ToArray();
        if (normalizedImagePaths.Length != 0 && normalizedImagePaths.Length != screenshotCount)
        {
            throw new ArgumentException("截图路径数量必须与证据截图数量一致。", nameof(evidenceImagePaths));
        }

        StartedAt = startedAt;
        CompletedAt = completedAt;
        ExecutionStatus = executionStatus;
        RawOutputPath = rawOutputPath;
        EvidenceImagePaths = new ReadOnlyCollection<string>(normalizedImagePaths);
        ScreenshotCount = screenshotCount;
        ShaStatus = shaStatus;
    }

    public string DeviceId { get; }
    public string DeviceName { get; }
    public string CommandId { get; }
    public string CommandText { get; }
    public DateTimeOffset StartedAt { get; }
    public DateTimeOffset? CompletedAt { get; }
    public ExecutionStatus ExecutionStatus { get; }
    public string? RawOutputPath { get; }
    public IReadOnlyList<string> EvidenceImagePaths { get; }
    public int ScreenshotCount { get; }
    public EvidenceShaStatus ShaStatus { get; }

    public string ExecutionStatusText
    {
        get
        {
            switch (ExecutionStatus)
            {
                case ExecutionStatus.Pending:
                    return "待执行";
                case ExecutionStatus.Running:
                    return "执行中";
                case ExecutionStatus.Succeeded:
                    return "成功";
                case ExecutionStatus.Failed:
                    return "失败";
                case ExecutionStatus.Skipped:
                    return "已跳过";
                case ExecutionStatus.Stopped:
                    return "已停止";
                default:
                    return "未知";
            }
        }
    }

    public string RawOutputPathText => RawOutputPath ?? "未生成";
    public bool HasRawOutput => RawOutputPath != null;
    public bool HasScreenshots => EvidenceImagePaths.Count != 0;
    public string? FirstScreenshotPath => EvidenceImagePaths.FirstOrDefault();
    public string ScreenshotCountText => ScreenshotCount + " 张";

    public string ShaStatusText
    {
        get
        {
            switch (ShaStatus)
            {
                case EvidenceShaStatus.Complete:
                    return "索引完整（未复核文件）";
                case EvidenceShaStatus.Verified:
                    return "文件与索引 SHA-256 一致";
                case EvidenceShaStatus.Missing:
                    return "证据或索引缺失";
                case EvidenceShaStatus.Mismatch:
                    return "SHA-256 不一致";
                case EvidenceShaStatus.UnsafePath:
                    return "证据路径不安全";
                case EvidenceShaStatus.Unavailable:
                    return "文件暂时无法读取";
                default:
                    return "暂无 SHA";
            }
        }
    }
}

public sealed class EvidenceCenterSnapshot
{
    public EvidenceCenterSnapshot(ProjectId projectId, IEnumerable<EvidenceCenterItem> items)
        : this(
            projectId,
            items,
            Array.Empty<DatabaseConfirmationAuditItem>(),
            Array.Empty<HostSoftwareDiscoveryAuditItem>())
    {
    }

    public EvidenceCenterSnapshot(
        ProjectId projectId,
        IEnumerable<EvidenceCenterItem> items,
        IEnumerable<DatabaseConfirmationAuditItem> databaseConfirmations)
        : this(
            projectId,
            items,
            databaseConfirmations,
            Array.Empty<HostSoftwareDiscoveryAuditItem>())
    {
    }

    public EvidenceCenterSnapshot(
        ProjectId projectId,
        IEnumerable<EvidenceCenterItem> items,
        IEnumerable<DatabaseConfirmationAuditItem> databaseConfirmations,
        IEnumerable<HostSoftwareDiscoveryAuditItem> hostSoftwareDiscoveries)
    {
        if (projectId.Equals(default(ProjectId)))
        {
            throw new ArgumentException("Project ID must be initialized.", nameof(projectId));
        }

        if (items == null)
        {
            throw new ArgumentNullException(nameof(items));
        }

        if (databaseConfirmations == null)
        {
            throw new ArgumentNullException(nameof(databaseConfirmations));
        }

        if (hostSoftwareDiscoveries == null)
        {
            throw new ArgumentNullException(nameof(hostSoftwareDiscoveries));
        }

        ProjectId = projectId;
        Items = new ReadOnlyCollection<EvidenceCenterItem>(items.ToArray());
        DatabaseConfirmations = new ReadOnlyCollection<DatabaseConfirmationAuditItem>(
            databaseConfirmations.ToArray());
        HostSoftwareDiscoveries = new ReadOnlyCollection<HostSoftwareDiscoveryAuditItem>(
            hostSoftwareDiscoveries.ToArray());
    }

    public ProjectId ProjectId { get; }
    public IReadOnlyList<EvidenceCenterItem> Items { get; }
    public IReadOnlyList<DatabaseConfirmationAuditItem> DatabaseConfirmations { get; }
    public IReadOnlyList<HostSoftwareDiscoveryAuditItem> HostSoftwareDiscoveries { get; }
}

public enum HostSoftwareAuditDecisionStatus
{
    Pending = 0,
    Confirmed = 1,
    Rejected = 2,
    Superseded = 3
}

public sealed class HostSoftwareDiscoveryAuditItem
{
    public HostSoftwareDiscoveryAuditItem(
        string deviceName,
        long batchRevision,
        DateTimeOffset batchRecordedAt,
        HostSoftwareCategory category,
        string product,
        string? version,
        HostSoftwareInstallationType installationType,
        string instanceName,
        string? portEvidence,
        double confidence,
        string evidenceSummary,
        HostSoftwareAuditDecisionStatus decisionStatus,
        string? decidedBy,
        string? decisionSource,
        string? decisionReason,
        DateTimeOffset? decidedAt)
    {
        DeviceName = Required(deviceName, nameof(deviceName));
        if (batchRevision < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(batchRevision));
        }

        if (batchRecordedAt == default(DateTimeOffset))
        {
            throw new ArgumentException("发现批次时间不能为空。", nameof(batchRecordedAt));
        }

        Category = RequireEnum(category, nameof(category));
        Product = Required(product, nameof(product));
        Version = version;
        InstallationType = RequireEnum(installationType, nameof(installationType));
        InstanceName = Required(instanceName, nameof(instanceName));
        PortEvidence = portEvidence;
        if (double.IsNaN(confidence) || double.IsInfinity(confidence) || confidence < 0 || confidence > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(confidence));
        }

        EvidenceSummary = Required(evidenceSummary, nameof(evidenceSummary));
        DecisionStatus = RequireEnum(decisionStatus, nameof(decisionStatus));
        if (decisionStatus == HostSoftwareAuditDecisionStatus.Pending)
        {
            if (decidedBy != null || decisionSource != null || decisionReason != null || decidedAt.HasValue)
            {
                throw new ArgumentException("未决候选不能包含人工决议信息。", nameof(decisionStatus));
            }
        }
        else if (string.IsNullOrWhiteSpace(decidedBy)
            || string.IsNullOrWhiteSpace(decisionSource)
            || !decidedAt.HasValue)
        {
            throw new ArgumentException("已决候选必须包含人员、来源和时间。", nameof(decisionStatus));
        }

        BatchRevision = batchRevision;
        BatchRecordedAt = batchRecordedAt.ToUniversalTime();
        Confidence = confidence;
        DecidedBy = decidedBy;
        DecisionSource = decisionSource;
        DecisionReason = decisionReason;
        DecidedAt = decidedAt?.ToUniversalTime();
    }

    public string DeviceName { get; }
    public long BatchRevision { get; }
    public DateTimeOffset BatchRecordedAt { get; }
    public HostSoftwareCategory Category { get; }
    public string Product { get; }
    public string? Version { get; }
    public HostSoftwareInstallationType InstallationType { get; }
    public string InstanceName { get; }
    public string? PortEvidence { get; }
    public double Confidence { get; }
    public string EvidenceSummary { get; }
    public HostSoftwareAuditDecisionStatus DecisionStatus { get; }
    public string? DecidedBy { get; }
    public string? DecisionSource { get; }
    public string? DecisionReason { get; }
    public DateTimeOffset? DecidedAt { get; }
    public string CategoryText => Category == HostSoftwareCategory.Database ? "数据库" : "中间件";
    public string VersionText => Version ?? "未识别";
    public string InstallationTypeText => InstallationType == HostSoftwareInstallationType.Container
        ? "容器"
        : "本地服务或进程";
    public string PortEvidenceText => PortEvidence ?? "未发现";
    public string BatchRecordedAtText => BatchRecordedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz");
    public string DecisionStatusText
    {
        get
        {
            switch (DecisionStatus)
            {
                case HostSoftwareAuditDecisionStatus.Pending:
                    return "待人工确认";
                case HostSoftwareAuditDecisionStatus.Confirmed:
                    return "已确认";
                case HostSoftwareAuditDecisionStatus.Rejected:
                    return "已排除";
                case HostSoftwareAuditDecisionStatus.Superseded:
                    return "已被新批次取代";
                default:
                    return "状态未知";
            }
        }
    }
    public string DecisionActorText => DecidedBy ?? "未决";
    public string DecisionReasonText => DecisionReason ?? "无";
    public string DecidedAtText => DecidedAt.HasValue
        ? DecidedAt.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz")
        : "尚未决议";

    private static string Required(string value, string parameterName)
    {
        return string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("主机软件发现审计字段不能为空。", parameterName)
            : value;
    }

    private static TEnum RequireEnum<TEnum>(TEnum value, string parameterName)
        where TEnum : struct
    {
        return Enum.IsDefined(typeof(TEnum), value)
            ? value
            : throw new ArgumentOutOfRangeException(parameterName);
    }
}

public sealed class DatabaseConfirmationAuditItem
{
    public DatabaseConfirmationAuditItem(
        string deviceName,
        string product,
        string? version,
        DatabaseInstallationType installationType,
        string instanceName,
        string? portEvidence,
        string detectionEvidence,
        double confidence,
        DateTimeOffset confirmedAt,
        string confirmationSource)
    {
        DeviceName = Required(deviceName, nameof(deviceName));
        Product = Required(product, nameof(product));
        Version = version;
        if (!Enum.IsDefined(typeof(DatabaseInstallationType), installationType))
        {
            throw new ArgumentOutOfRangeException(nameof(installationType));
        }

        if (double.IsNaN(confidence) || double.IsInfinity(confidence) || confidence < 0 || confidence > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(confidence));
        }

        InstallationType = installationType;
        InstanceName = Required(instanceName, nameof(instanceName));
        PortEvidence = portEvidence;
        DetectionEvidence = Required(detectionEvidence, nameof(detectionEvidence));
        Confidence = confidence;
        ConfirmedAt = confirmedAt;
        ConfirmationSource = Required(confirmationSource, nameof(confirmationSource));
    }

    public string DeviceName { get; }
    public string Product { get; }
    public string? Version { get; }
    public DatabaseInstallationType InstallationType { get; }
    public string InstanceName { get; }
    public string? PortEvidence { get; }
    public string DetectionEvidence { get; }
    public double Confidence { get; }
    public DateTimeOffset ConfirmedAt { get; }
    public string ConfirmationSource { get; }
    public string VersionText => Version ?? "未识别";
    public string PortEvidenceText => PortEvidence ?? "未发现";
    public string InstallationTypeText => InstallationType == DatabaseInstallationType.Container
        ? "容器"
        : "本机服务";
    public string ConfirmedAtText => ConfirmedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz");

    private static string Required(string value, string parameterName)
    {
        return string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("人工确认审计字段不能为空。", parameterName)
            : value;
    }
}

public interface IEvidenceCenterService
{
    Task<EvidenceCenterSnapshot> LoadAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default);
    Task<EvidenceCenterSnapshot> VerifyAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default);
}

public sealed class EvidenceCenterService : IEvidenceCenterService
{
    private readonly IProjectRepository repository;
    private readonly IDatabaseConfirmationRepository databaseConfirmationRepository;
    private readonly IHostSoftwareDiscoveryRepository hostSoftwareDiscoveryRepository;
    private readonly EvidenceFileIntegrityVerifier integrityVerifier;

    public EvidenceCenterService(IProjectRepository repository)
        : this(
            repository,
            repository as IDatabaseConfirmationRepository
                ?? throw new ArgumentException(
                    "证据中心仓储必须支持数据库人工确认审计读取。",
                    nameof(repository)),
            repository as IHostSoftwareDiscoveryRepository
                ?? throw new ArgumentException(
                    "证据中心仓储必须支持主机软件发现及人工决议审计读取。",
                    nameof(repository)),
            new EvidenceFileIntegrityVerifier())
    {
    }

    public EvidenceCenterService(
        IProjectRepository repository,
        IDatabaseConfirmationRepository databaseConfirmationRepository)
        : this(
            repository,
            databaseConfirmationRepository,
            repository as IHostSoftwareDiscoveryRepository
                ?? throw new ArgumentException(
                    "证据中心仓储必须支持主机软件发现及人工决议审计读取。",
                    nameof(repository)),
            new EvidenceFileIntegrityVerifier())
    {
    }

    public EvidenceCenterService(
        IProjectRepository repository,
        IDatabaseConfirmationRepository databaseConfirmationRepository,
        IHostSoftwareDiscoveryRepository hostSoftwareDiscoveryRepository)
        : this(
            repository,
            databaseConfirmationRepository,
            hostSoftwareDiscoveryRepository,
            new EvidenceFileIntegrityVerifier())
    {
    }

    internal EvidenceCenterService(
        IProjectRepository repository,
        IDatabaseConfirmationRepository databaseConfirmationRepository,
        IHostSoftwareDiscoveryRepository hostSoftwareDiscoveryRepository,
        EvidenceFileIntegrityVerifier integrityVerifier)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
        this.databaseConfirmationRepository = databaseConfirmationRepository
            ?? throw new ArgumentNullException(nameof(databaseConfirmationRepository));
        this.hostSoftwareDiscoveryRepository = hostSoftwareDiscoveryRepository
            ?? throw new ArgumentNullException(nameof(hostSoftwareDiscoveryRepository));
        this.integrityVerifier = integrityVerifier ?? throw new ArgumentNullException(nameof(integrityVerifier));
    }

    public async Task<EvidenceCenterSnapshot> LoadAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default)
    {
        return await LoadCoreAsync(projectId, verifyFiles: false, cancellationToken).ConfigureAwait(false);
    }

    public Task<EvidenceCenterSnapshot> VerifyAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default)
    {
        return LoadCoreAsync(projectId, verifyFiles: true, cancellationToken);
    }

    private async Task<EvidenceCenterSnapshot> LoadCoreAsync(
        ProjectId projectId,
        bool verifyFiles,
        CancellationToken cancellationToken)
    {
        if (projectId.Equals(default(ProjectId)))
        {
            throw new EvidenceCenterException(
                EvidenceCenterFailure.InvalidProject,
                "请先选择有效项目后再加载证据记录。");
        }

        try
        {
            var executions = await repository.GetExecutionsAsync(projectId, cancellationToken)
                .ConfigureAwait(false);
            var evidenceFiles = await repository.GetEvidenceFilesAsync(projectId, cancellationToken)
                .ConfigureAwait(false);
            var devices = await repository.GetDevicesAsync(projectId, cancellationToken)
                .ConfigureAwait(false);
            var confirmations = await databaseConfirmationRepository
                .GetDatabaseConfirmationsAsync(projectId, cancellationToken)
                .ConfigureAwait(false);
            var hostSoftwareItems = await LoadHostSoftwareAuditAsync(devices, cancellationToken)
                .ConfigureAwait(false);
            string? evidenceRoot = null;
            if (verifyFiles)
            {
                var projects = await repository.GetProjectsAsync(cancellationToken).ConfigureAwait(false);
                var persistedProject = projects.SingleOrDefault(project => project.Id.Equals(projectId));
                if (persistedProject == null)
                {
                    throw new EvidenceCenterException(
                        EvidenceCenterFailure.InvalidProject,
                        "当前项目不存在，已阻止读取证据目录。");
                }

                evidenceRoot = persistedProject.EvidenceRoot;
            }
            cancellationToken.ThrowIfCancellationRequested();

            if (executions == null || evidenceFiles == null || devices == null || confirmations == null)
            {
                throw new InvalidOperationException("Repository returned no evidence index result.");
            }

            var evidenceIndex = EvidenceIndex.Create(evidenceFiles);
            var deviceNames = devices.ToDictionary(
                device => device.Id.ToString(),
                device => device.DisplayName,
                StringComparer.OrdinalIgnoreCase);
            var items = executions
                .Select(execution => CreateItem(
                    execution,
                    evidenceIndex,
                    deviceNames,
                    evidenceRoot,
                    cancellationToken))
                .OrderByDescending(item => item.StartedAt)
                .ThenBy(item => item.DeviceId, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.CommandId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var confirmationItems = confirmations
                .Select(confirmation => new DatabaseConfirmationAuditItem(
                    deviceNames.TryGetValue(confirmation.DeviceId.ToString(), out var deviceName)
                        ? deviceName
                        : "未知设备（" + confirmation.DeviceId + "）",
                    confirmation.Product,
                    confirmation.Version,
                    confirmation.InstallationType,
                    confirmation.InstanceName,
                    confirmation.PortEvidence,
                    confirmation.DetectionEvidence,
                    confirmation.Confidence,
                    confirmation.ConfirmedAt,
                    confirmation.ConfirmationSource))
                .OrderByDescending(item => item.ConfirmedAt)
                .ThenBy(item => item.DeviceName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.Product, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return new EvidenceCenterSnapshot(projectId, items, confirmationItems, hostSoftwareItems);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (EvidenceCenterException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new EvidenceCenterException(
                verifyFiles
                    ? EvidenceCenterFailure.VerificationUnavailable
                    : EvidenceCenterFailure.IndexUnavailable,
                verifyFiles
                    ? "证据文件复核暂时无法完成。请确认项目数据库和证据目录可访问后重试。"
                    : "证据索引暂时无法读取。请确认本地项目数据库可用后重试。");
        }
    }

    private async Task<IReadOnlyList<HostSoftwareDiscoveryAuditItem>> LoadHostSoftwareAuditAsync(
        IReadOnlyList<DeviceRecord> devices,
        CancellationToken cancellationToken)
    {
        if (devices == null)
        {
            throw new InvalidOperationException("Repository returned no device index result.");
        }

        var entries = new List<HostSoftwareAuditEntry>();
        foreach (var device in devices
            .OrderBy(item => item.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Id.ToString(), StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var batches = await hostSoftwareDiscoveryRepository
                .GetHostSoftwareDiscoveryHistoryAsync(device.Id, cancellationToken)
                .ConfigureAwait(false);
            if (batches == null)
            {
                throw new InvalidOperationException("Repository returned no host software discovery history.");
            }

            foreach (var batch in batches)
            {
                if (batch == null
                    || !batch.DeviceId.Equals(device.Id)
                    || !batch.ProjectId.Equals(device.ProjectId))
                {
                    throw new InvalidOperationException("Host software discovery history contains an invalid device batch.");
                }

                var decisions = await hostSoftwareDiscoveryRepository
                    .GetHostSoftwareCandidateDecisionsAsync(batch.BatchId, cancellationToken)
                    .ConfigureAwait(false);
                if (decisions == null)
                {
                    throw new InvalidOperationException("Repository returned no host software decision history.");
                }

                var decisionsByCandidate = decisions
                    .GroupBy(decision => decision.CandidateId)
                    .ToDictionary(
                        group => group.Key,
                        group => group.Single());
                var candidateIds = new HashSet<Guid>(
                    batch.Candidates.Select(candidate => candidate.CandidateId));
                if (decisionsByCandidate.Keys.Any(candidateId => !candidateIds.Contains(candidateId)))
                {
                    throw new InvalidOperationException(
                        "Host software decision history contains a candidate from another batch.");
                }
                foreach (var candidate in batch.Candidates)
                {
                    HostSoftwareCandidateDecisionRecord? decision;
                    decisionsByCandidate.TryGetValue(candidate.CandidateId, out decision);
                    entries.Add(new HostSoftwareAuditEntry(
                        batch.RecordedAt,
                        device.DisplayName,
                        batch.Revision,
                        candidate.Ordinal,
                        CreateHostSoftwareAuditItem(device.DisplayName, batch, candidate, decision)));
                }
            }
        }

        return entries
            .OrderByDescending(entry => entry.RecordedAt)
            .ThenBy(entry => entry.DeviceName, StringComparer.OrdinalIgnoreCase)
            .ThenByDescending(entry => entry.Revision)
            .ThenBy(entry => entry.CandidateOrdinal)
            .Select(entry => entry.Item)
            .ToArray();
    }

    private static HostSoftwareDiscoveryAuditItem CreateHostSoftwareAuditItem(
        string deviceName,
        HostSoftwareDiscoveryBatchRecord batch,
        HostSoftwareDiscoveryCandidateRecord candidate,
        HostSoftwareCandidateDecisionRecord? decision)
    {
        return new HostSoftwareDiscoveryAuditItem(
            deviceName,
            batch.Revision,
            batch.RecordedAt,
            candidate.Category,
            candidate.Product,
            candidate.Version,
            candidate.InstallationType,
            candidate.InstanceName,
            candidate.PortEvidence,
            candidate.Confidence,
            string.Join("；", candidate.Sources
                .OrderBy(source => source.Ordinal)
                .Select(source => GetEvidenceKindText(source.Kind) + "：" + source.Excerpt)),
            decision == null
                ? HostSoftwareAuditDecisionStatus.Pending
                : MapDecisionStatus(decision.Decision),
            decision?.DecidedBy,
            decision?.DecisionSource,
            decision?.Reason,
            decision?.DecidedAt);
    }

    private static HostSoftwareAuditDecisionStatus MapDecisionStatus(HostSoftwareCandidateDecision decision)
    {
        switch (decision)
        {
            case HostSoftwareCandidateDecision.Confirmed:
                return HostSoftwareAuditDecisionStatus.Confirmed;
            case HostSoftwareCandidateDecision.Rejected:
                return HostSoftwareAuditDecisionStatus.Rejected;
            case HostSoftwareCandidateDecision.Superseded:
                return HostSoftwareAuditDecisionStatus.Superseded;
            default:
                throw new InvalidOperationException("Host software decision contains an invalid status.");
        }
    }

    private static string GetEvidenceKindText(HostSoftwareEvidenceKind kind)
    {
        switch (kind)
        {
            case HostSoftwareEvidenceKind.Service:
                return "服务";
            case HostSoftwareEvidenceKind.Process:
                return "进程";
            case HostSoftwareEvidenceKind.Package:
                return "软件包";
            case HostSoftwareEvidenceKind.Container:
                return "容器";
            case HostSoftwareEvidenceKind.ListeningEndpoint:
                return "监听端点";
            case HostSoftwareEvidenceKind.CommandOutput:
                return "命令输出";
            default:
                throw new InvalidOperationException("Host software evidence contains an invalid kind.");
        }
    }

    private sealed class HostSoftwareAuditEntry
    {
        internal HostSoftwareAuditEntry(
            DateTimeOffset recordedAt,
            string deviceName,
            long revision,
            int candidateOrdinal,
            HostSoftwareDiscoveryAuditItem item)
        {
            RecordedAt = recordedAt;
            DeviceName = deviceName;
            Revision = revision;
            CandidateOrdinal = candidateOrdinal;
            Item = item;
        }

        internal DateTimeOffset RecordedAt { get; }
        internal string DeviceName { get; }
        internal long Revision { get; }
        internal int CandidateOrdinal { get; }
        internal HostSoftwareDiscoveryAuditItem Item { get; }
    }

    private EvidenceCenterItem CreateItem(
        ExecutionRecord execution,
        EvidenceIndex evidenceIndex,
        IReadOnlyDictionary<string, string> deviceNames,
        string? evidenceRoot,
        CancellationToken cancellationToken)
    {
        if (execution == null)
        {
            throw new InvalidOperationException("Evidence index contains an empty execution record.");
        }

        return new EvidenceCenterItem(
            execution.DeviceId,
            deviceNames.TryGetValue(execution.DeviceId, out var deviceName)
                ? deviceName
                : "未知设备（" + execution.DeviceId + "）",
            execution.CommandId,
            execution.CommandText,
            execution.StartedAt,
            execution.CompletedAt,
            execution.Status,
            execution.RawOutputPath,
            execution.EvidenceImagePaths,
            execution.EvidenceImagePaths.Count,
            EvaluateShaStatus(execution, evidenceIndex, evidenceRoot, cancellationToken));
    }

    private EvidenceShaStatus EvaluateShaStatus(
        ExecutionRecord execution,
        EvidenceIndex evidenceIndex,
        string? evidenceRoot,
        CancellationToken cancellationToken)
    {
        var expectedCount = (execution.RawOutputPath == null ? 0 : 1)
            + execution.EvidenceImagePaths.Count;
        if (expectedCount == 0)
        {
            return EvidenceShaStatus.NotAvailable;
        }

        var missing = false;
        var mismatch = false;
        if (execution.RawOutputPath != null)
        {
            EvaluateExpectedFile(
                evidenceIndex,
                execution.DeviceId,
                execution.RawOutputPath,
                EvidenceFileKind.RawOutput,
                execution.RawOutputSha256,
                ref missing,
                ref mismatch);
        }

        foreach (var imagePath in execution.EvidenceImagePaths)
        {
            string expectedHash;
            if (!execution.EvidenceImageSha256s.TryGetValue(imagePath, out expectedHash))
            {
                missing = true;
                continue;
            }

            EvaluateExpectedFile(
                evidenceIndex,
                execution.DeviceId,
                imagePath,
                EvidenceFileKind.EvidenceImage,
                expectedHash,
                ref missing,
                ref mismatch);
        }

        if (mismatch)
        {
            return EvidenceShaStatus.Mismatch;
        }

        if (missing)
        {
            return EvidenceShaStatus.Missing;
        }

        if (evidenceRoot == null)
        {
            return EvidenceShaStatus.Complete;
        }

        var expectedFiles = new List<ExpectedEvidenceFile>();
        if (execution.RawOutputPath != null && execution.RawOutputSha256 != null)
        {
            expectedFiles.Add(new ExpectedEvidenceFile(
                execution.RawOutputPath,
                execution.RawOutputSha256));
        }

        foreach (var imagePath in execution.EvidenceImagePaths)
        {
            expectedFiles.Add(new ExpectedEvidenceFile(
                imagePath,
                execution.EvidenceImageSha256s[imagePath]));
        }

        return integrityVerifier.Verify(evidenceRoot, expectedFiles, cancellationToken);
    }

    private static void EvaluateExpectedFile(
        EvidenceIndex index,
        string deviceId,
        string relativePath,
        EvidenceFileKind expectedKind,
        string? expectedHash,
        ref bool missing,
        ref bool mismatch)
    {
        var records = index.Find(deviceId, relativePath);
        if (records.Count == 0)
        {
            missing = true;
            return;
        }

        if (records.Count != 1
            || records[0].Kind != expectedKind
            || expectedHash == null
            || !string.Equals(records[0].Sha256, expectedHash, StringComparison.OrdinalIgnoreCase))
        {
            mismatch = true;
        }
    }

    private sealed class EvidenceIndex
    {
        private readonly IReadOnlyDictionary<string, IReadOnlyList<EvidenceFileRecord>> recordsByPath;

        private EvidenceIndex(IReadOnlyDictionary<string, IReadOnlyList<EvidenceFileRecord>> recordsByPath)
        {
            this.recordsByPath = recordsByPath;
        }

        internal static EvidenceIndex Create(IEnumerable<EvidenceFileRecord> files)
        {
            var groups = new Dictionary<string, List<EvidenceFileRecord>>(StringComparer.OrdinalIgnoreCase);
            foreach (var file in files)
            {
                if (file == null)
                {
                    throw new InvalidOperationException("Evidence index contains an empty file record.");
                }

                var key = CreateKey(file.DeviceId.ToString(), file.RelativePath);
                List<EvidenceFileRecord> records;
                if (!groups.TryGetValue(key, out records))
                {
                    records = new List<EvidenceFileRecord>();
                    groups.Add(key, records);
                }

                records.Add(file);
            }

            return new EvidenceIndex(groups.ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<EvidenceFileRecord>)group.Value.AsReadOnly(),
                StringComparer.OrdinalIgnoreCase));
        }

        internal IReadOnlyList<EvidenceFileRecord> Find(string deviceId, string relativePath)
        {
            IReadOnlyList<EvidenceFileRecord> records;
            return recordsByPath.TryGetValue(CreateKey(deviceId, relativePath), out records)
                ? records
                : Array.Empty<EvidenceFileRecord>();
        }

        private static string CreateKey(string deviceId, string relativePath)
        {
            return deviceId + "\n" + relativePath;
        }
    }
}
