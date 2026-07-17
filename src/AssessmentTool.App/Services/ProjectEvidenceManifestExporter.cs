using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AssessmentTool.App.Services;

public interface IProjectEvidenceManifestExporter
{
    Task<EvidenceManifestExportResult> ExportAsync(
        ProjectRecord project,
        string destinationPath,
        CancellationToken cancellationToken = default);
}

public interface IEvidenceManifestExportFilePicker
{
    string? SelectDestination(ProjectRecord project);
}

public sealed class EvidenceManifestExportResult
{
    public EvidenceManifestExportResult(
        string path,
        int executionCount,
        int evidenceFileCount,
        int discoveryBatchCount)
    {
        Path = path ?? throw new ArgumentNullException(nameof(path));
        ExecutionCount = executionCount;
        EvidenceFileCount = evidenceFileCount;
        DiscoveryBatchCount = discoveryBatchCount;
    }

    public string Path { get; }
    public int ExecutionCount { get; }
    public int EvidenceFileCount { get; }
    public int DiscoveryBatchCount { get; }
    public string Summary => "已导出 " + ExecutionCount + " 条执行、"
        + EvidenceFileCount + " 个证据文件索引和 " + DiscoveryBatchCount + " 个发现批次。";
}

public sealed class JsonEvidenceManifestExportFilePicker : IEvidenceManifestExportFilePicker
{
    public string? SelectDestination(ProjectRecord project)
    {
        if (project == null)
        {
            throw new ArgumentNullException(nameof(project));
        }

        var dialog = new SaveFileDialog
        {
            Title = "导出项目证据清单",
            Filter = "JSON 清单 (*.json)|*.json",
            AddExtension = true,
            DefaultExt = ".json",
            FileName = SafeFileName(project.ProjectName)
                + "-证据清单-" + DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)
                + ".json",
            CheckPathExists = true,
            OverwritePrompt = false
        };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    private static string SafeFileName(string value)
    {
        var invalid = new HashSet<char>(Path.GetInvalidFileNameChars());
        var normalized = new string(value.Select(character => invalid.Contains(character) ? '_' : character).ToArray())
            .Trim(' ', '.');
        return string.IsNullOrWhiteSpace(normalized) ? "EvaluationTool" : normalized;
    }
}

public sealed class ProjectEvidenceManifestExporter : IProjectEvidenceManifestExporter
{
    private const int MaximumExportRecords = 200000;
    private readonly IProjectRepository repository;
    private readonly IDatabaseConfirmationRepository databaseConfirmationRepository;
    private readonly IHostSoftwareDiscoveryRepository hostSoftwareDiscoveryRepository;
    private readonly IEvidenceCenterService evidenceCenterService;
    private readonly Func<DateTimeOffset> utcNow;

    public ProjectEvidenceManifestExporter(IProjectRepository repository)
        : this(
            repository,
            repository as IDatabaseConfirmationRepository
                ?? throw new ArgumentException("仓储不支持数据库确认审计导出。", nameof(repository)),
            repository as IHostSoftwareDiscoveryRepository
                ?? throw new ArgumentException("仓储不支持主机软件发现审计导出。", nameof(repository)),
            new EvidenceCenterService(repository),
            () => DateTimeOffset.UtcNow)
    {
    }

    internal ProjectEvidenceManifestExporter(
        IProjectRepository repository,
        IDatabaseConfirmationRepository databaseConfirmationRepository,
        IHostSoftwareDiscoveryRepository hostSoftwareDiscoveryRepository,
        IEvidenceCenterService evidenceCenterService,
        Func<DateTimeOffset> utcNow)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
        this.databaseConfirmationRepository = databaseConfirmationRepository
            ?? throw new ArgumentNullException(nameof(databaseConfirmationRepository));
        this.hostSoftwareDiscoveryRepository = hostSoftwareDiscoveryRepository
            ?? throw new ArgumentNullException(nameof(hostSoftwareDiscoveryRepository));
        this.evidenceCenterService = evidenceCenterService
            ?? throw new ArgumentNullException(nameof(evidenceCenterService));
        this.utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));
    }

    public async Task<EvidenceManifestExportResult> ExportAsync(
        ProjectRecord project,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        if (project == null)
        {
            throw new ArgumentNullException(nameof(project));
        }

        var targetPath = ValidateDestination(destinationPath);
        var projects = await repository.GetProjectsAsync(cancellationToken).ConfigureAwait(false);
        var persistedProject = projects.SingleOrDefault(item => item.Id.Equals(project.Id));
        if (persistedProject == null)
        {
            throw new InvalidOperationException("当前项目不存在，已阻止导出证据清单。");
        }

        var devices = await repository.GetDevicesAsync(project.Id, cancellationToken).ConfigureAwait(false);
        var executions = await repository.GetExecutionsAsync(project.Id, cancellationToken).ConfigureAwait(false);
        var evidenceFiles = await repository.GetEvidenceFilesAsync(project.Id, cancellationToken).ConfigureAwait(false);
        var confirmations = await databaseConfirmationRepository
            .GetDatabaseConfirmationsAsync(project.Id, cancellationToken).ConfigureAwait(false);
        var verifiedSnapshot = await evidenceCenterService.VerifyAsync(project.Id, cancellationToken)
            .ConfigureAwait(false);
        if (!verifiedSnapshot.ProjectId.Equals(project.Id))
        {
            throw new InvalidDataException("证据复核结果属于其他项目。");
        }
        var integrityByExecution = verifiedSnapshot.Items.ToDictionary(
            item => CreateExecutionKey(item.DeviceId, item.CommandId, item.StartedAt),
            item => item.ShaStatus);
        if (integrityByExecution.Count != executions.Count)
        {
            throw new InvalidDataException("执行记录与证据复核结果数量不一致。");
        }
        EnsureCount(devices.Count + executions.Count + evidenceFiles.Count + confirmations.Count);

        var deviceNames = devices.ToDictionary(device => device.Id, device => device.DisplayName);
        var discoveryBatches = new List<HostSoftwareDiscoveryBatchRecord>();
        var decisionsByBatch = new Dictionary<Guid, IReadOnlyList<HostSoftwareCandidateDecisionRecord>>();
        foreach (var device in devices.OrderBy(item => item.DisplayName, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var batches = await hostSoftwareDiscoveryRepository
                .GetHostSoftwareDiscoveryHistoryAsync(device.Id, cancellationToken).ConfigureAwait(false);
            foreach (var batch in batches)
            {
                if (!batch.ProjectId.Equals(project.Id) || !batch.DeviceId.Equals(device.Id))
                {
                    throw new InvalidDataException("主机软件发现历史包含其他项目或设备的数据。");
                }

                var decisions = await hostSoftwareDiscoveryRepository
                    .GetHostSoftwareCandidateDecisionsAsync(batch.BatchId, cancellationToken)
                    .ConfigureAwait(false);
                var candidateIds = new HashSet<Guid>(batch.Candidates.Select(candidate => candidate.CandidateId));
                if (decisions.Any(decision => !candidateIds.Contains(decision.CandidateId)))
                {
                    throw new InvalidDataException("主机软件决议历史包含其他发现批次的数据。");
                }

                discoveryBatches.Add(batch);
                decisionsByBatch.Add(batch.BatchId, decisions);
                EnsureCount(devices.Count + executions.Count + evidenceFiles.Count + confirmations.Count
                    + discoveryBatches.Count + discoveryBatches.Sum(item => item.Candidates.Count)
                    + decisionsByBatch.Values.Sum(items => items.Count));
            }
        }

        var document = BuildDocument(
            persistedProject,
            devices,
            executions,
            evidenceFiles,
            confirmations,
            discoveryBatches,
            decisionsByBatch,
            deviceNames,
            integrityByExecution,
            utcNow().ToUniversalTime());
        WriteAtomically(targetPath, document, cancellationToken);
        return new EvidenceManifestExportResult(
            targetPath,
            executions.Count,
            evidenceFiles.Count,
            discoveryBatches.Count);
    }

    private static JObject BuildDocument(
        ProjectRecord project,
        IReadOnlyList<DeviceRecord> devices,
        IReadOnlyList<ExecutionRecord> executions,
        IReadOnlyList<EvidenceFileRecord> evidenceFiles,
        IReadOnlyList<DatabaseConfirmationRecord> confirmations,
        IReadOnlyList<HostSoftwareDiscoveryBatchRecord> discoveryBatches,
        IReadOnlyDictionary<Guid, IReadOnlyList<HostSoftwareCandidateDecisionRecord>> decisionsByBatch,
        IReadOnlyDictionary<DeviceId, string> deviceNames,
        IReadOnlyDictionary<string, EvidenceShaStatus> integrityByExecution,
        DateTimeOffset generatedAt)
    {
        return new JObject
        {
            ["schemaVersion"] = 1,
            ["documentType"] = "EvaluationTool.ProjectEvidenceManifest",
            ["generatedAtUtc"] = generatedAt.ToString("O", CultureInfo.InvariantCulture),
            ["exportNotice"] = "本文件仅包含本地证据索引和审计元数据，不包含密码、私钥、令牌或原始输出正文。",
            ["verificationMode"] = "导出前已只读复算证据文件 SHA-256；本清单不是第三方数字签名。",
            ["project"] = new JObject
            {
                ["id"] = project.Id.ToString(),
                ["customerName"] = project.CustomerName,
                ["projectName"] = project.ProjectName,
                ["createdAtUtc"] = project.CreatedAt.ToString("O", CultureInfo.InvariantCulture)
            },
            ["summary"] = new JObject
            {
                ["deviceCount"] = devices.Count,
                ["executionCount"] = executions.Count,
                ["evidenceFileCount"] = evidenceFiles.Count,
                ["databaseConfirmationCount"] = confirmations.Count,
                ["hostSoftwareDiscoveryBatchCount"] = discoveryBatches.Count,
                ["verifiedExecutionCount"] = integrityByExecution.Values.Count(status => status == EvidenceShaStatus.Verified),
                ["problemExecutionCount"] = integrityByExecution.Values.Count(status => status != EvidenceShaStatus.Verified
                    && status != EvidenceShaStatus.NotAvailable)
            },
            ["devices"] = new JArray(devices
                .OrderBy(device => device.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(device => device.Id.ToString(), StringComparer.OrdinalIgnoreCase)
                .Select(device => new JObject
                {
                    ["id"] = device.Id.ToString(),
                    ["displayName"] = device.DisplayName,
                    ["category"] = device.Category.ToString(),
                    ["protocol"] = device.Protocol.ToString()
                })),
            ["executions"] = new JArray(executions
                .OrderBy(execution => execution.StartedAt)
                .ThenBy(execution => execution.DeviceId, StringComparer.OrdinalIgnoreCase)
                .ThenBy(execution => execution.CommandId, StringComparer.OrdinalIgnoreCase)
                .Select(execution => new JObject
                {
                    ["deviceId"] = execution.DeviceId,
                    ["deviceName"] = FindDeviceName(deviceNames, execution.DeviceId),
                    ["connectionProtocol"] = execution.ConnectionProtocol.ToString(),
                    ["commandPackVersion"] = execution.CommandPackVersion,
                    ["commandId"] = execution.CommandId,
                    ["commandText"] = execution.CommandText,
                    ["startedAtUtc"] = execution.StartedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                    ["completedAtUtc"] = execution.CompletedAt.HasValue
                        ? execution.CompletedAt.Value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)
                        : null,
                    ["status"] = execution.Status.ToString(),
                    ["exitCode"] = execution.ExitCode,
                    ["integrityStatus"] = FindIntegrityStatus(integrityByExecution, execution),
                    ["rawOutputPath"] = execution.RawOutputPath,
                    ["rawOutputSha256"] = execution.RawOutputSha256,
                    ["evidenceImages"] = new JArray(execution.EvidenceImagePaths.Select(path => new JObject
                    {
                        ["relativePath"] = path,
                        ["sha256"] = execution.EvidenceImageSha256s[path]
                    }))
                })),
            ["evidenceFiles"] = new JArray(evidenceFiles
                .OrderBy(file => file.CreatedAt)
                .ThenBy(file => file.DeviceId.ToString(), StringComparer.OrdinalIgnoreCase)
                .ThenBy(file => file.Ordinal)
                .Select(file => new JObject
                {
                    ["deviceId"] = file.DeviceId.ToString(),
                    ["deviceName"] = deviceNames.TryGetValue(file.DeviceId, out var name) ? name : "未知设备",
                    ["relativePath"] = file.RelativePath,
                    ["sha256"] = file.Sha256,
                    ["kind"] = file.Kind.ToString(),
                    ["ordinal"] = file.Ordinal,
                    ["createdAtUtc"] = file.CreatedAt.ToString("O", CultureInfo.InvariantCulture)
                })),
            ["databaseConfirmations"] = new JArray(confirmations
                .OrderBy(confirmation => confirmation.ConfirmedAt)
                .Select(confirmation => new JObject
                {
                    ["deviceId"] = confirmation.DeviceId.ToString(),
                    ["deviceName"] = deviceNames.TryGetValue(confirmation.DeviceId, out var name) ? name : "未知设备",
                    ["product"] = confirmation.Product,
                    ["version"] = confirmation.Version,
                    ["installationType"] = confirmation.InstallationType.ToString(),
                    ["instanceName"] = confirmation.InstanceName,
                    ["portEvidence"] = confirmation.PortEvidence,
                    ["detectionEvidence"] = confirmation.DetectionEvidence,
                    ["confidence"] = confirmation.Confidence,
                    ["confirmedAtUtc"] = confirmation.ConfirmedAt.ToString("O", CultureInfo.InvariantCulture),
                    ["confirmationSource"] = confirmation.ConfirmationSource
                })),
            ["hostSoftwareDiscoveryBatches"] = new JArray(discoveryBatches
                .OrderBy(batch => batch.RecordedAt)
                .ThenBy(batch => batch.DeviceId.ToString(), StringComparer.OrdinalIgnoreCase)
                .ThenBy(batch => batch.Revision)
                .Select(batch => CreateDiscoveryBatch(batch, decisionsByBatch[batch.BatchId], deviceNames)))
        };
    }

    private static JObject CreateDiscoveryBatch(
        HostSoftwareDiscoveryBatchRecord batch,
        IReadOnlyList<HostSoftwareCandidateDecisionRecord> decisions,
        IReadOnlyDictionary<DeviceId, string> deviceNames)
    {
        var decisionsByCandidate = decisions.ToDictionary(decision => decision.CandidateId);
        return new JObject
        {
            ["batchId"] = batch.BatchId.ToString("D"),
            ["deviceId"] = batch.DeviceId.ToString(),
            ["deviceName"] = deviceNames.TryGetValue(batch.DeviceId, out var name) ? name : "未知设备",
            ["collectionTaskId"] = batch.CollectionTaskId.ToString(),
            ["revision"] = batch.Revision,
            ["previousBatchId"] = batch.PreviousBatchId?.ToString("D"),
            ["discoverySource"] = batch.DiscoverySource,
            ["recordedAtUtc"] = batch.RecordedAt.ToString("O", CultureInfo.InvariantCulture),
            ["candidates"] = new JArray(batch.Candidates.Select(candidate =>
            {
                decisionsByCandidate.TryGetValue(candidate.CandidateId, out var decision);
                return new JObject
                {
                    ["candidateId"] = candidate.CandidateId.ToString("D"),
                    ["ordinal"] = candidate.Ordinal,
                    ["category"] = candidate.Category.ToString(),
                    ["product"] = candidate.Product,
                    ["version"] = candidate.Version,
                    ["installationType"] = candidate.InstallationType.ToString(),
                    ["instanceName"] = candidate.InstanceName,
                    ["portEvidence"] = candidate.PortEvidence,
                    ["confidence"] = candidate.Confidence,
                    ["sources"] = new JArray(candidate.Sources.Select(source => new JObject
                    {
                        ["kind"] = source.Kind.ToString(),
                        ["sourceCommandId"] = source.SourceCommandId,
                        ["excerpt"] = source.Excerpt,
                        ["rawOutputSha256"] = source.RawOutputSha256
                    })),
                    ["decision"] = decision == null ? null : new JObject
                    {
                        ["status"] = decision.Decision.ToString(),
                        ["decidedBy"] = decision.DecidedBy,
                        ["decisionSource"] = decision.DecisionSource,
                        ["reason"] = decision.Reason,
                        ["decidedAtUtc"] = decision.DecidedAt.ToString("O", CultureInfo.InvariantCulture)
                    }
                };
            }))
        };
    }

    private static string FindDeviceName(
        IReadOnlyDictionary<DeviceId, string> names,
        string deviceId)
    {
        try
        {
            return names.TryGetValue(DeviceId.Parse(deviceId), out var name)
                ? name
                : "未知设备";
        }
        catch (ArgumentException)
        {
            return "未知设备";
        }
    }

    private static string FindIntegrityStatus(
        IReadOnlyDictionary<string, EvidenceShaStatus> statuses,
        ExecutionRecord execution)
    {
        if (!statuses.TryGetValue(
            CreateExecutionKey(execution.DeviceId, execution.CommandId, execution.StartedAt),
            out var status))
        {
            throw new InvalidDataException("执行记录缺少对应的证据复核状态。");
        }

        return status.ToString();
    }

    private static string CreateExecutionKey(string deviceId, string commandId, DateTimeOffset startedAt)
    {
        return deviceId + "\n" + commandId + "\n"
            + startedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    }

    private static string ValidateDestination(string path)
    {
        if (string.IsNullOrWhiteSpace(path)
            || path.Any(character => character == '\0' || character == '\r' || character == '\n'))
        {
            throw new ArgumentException("请选择有效的 JSON 导出路径。", nameof(path));
        }

        var fullPath = Path.GetFullPath(path);
        if (!Path.IsPathRooted(path))
        {
            throw new ArgumentException("导出路径必须是完整绝对路径。", nameof(path));
        }
        if (fullPath.StartsWith(@"\\?\", StringComparison.Ordinal)
            || fullPath.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            throw new ArgumentException("导出路径不能使用 Windows 设备路径。", nameof(path));
        }
        if (!string.Equals(Path.GetExtension(fullPath), ".json", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("项目证据清单必须导出为 .json 文件。", nameof(path));
        }

        var directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException("导出目录不存在。");
        }

        EnsureNoReparsePoints(directory);

        if (File.Exists(fullPath))
        {
            throw new IOException("目标文件已存在。为避免覆盖审计清单，请使用新的文件名。");
        }

        return fullPath;
    }

    private static void EnsureNoReparsePoints(string directory)
    {
        var current = new DirectoryInfo(directory);
        while (current != null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("导出目录或其上级目录包含 Windows 重解析点。");
            }

            current = current.Parent;
        }
    }

    private static void WriteAtomically(string targetPath, JObject document, CancellationToken cancellationToken)
    {
        var temporaryPath = targetPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var json = document.ToString(Formatting.Indented);
            cancellationToken.ThrowIfCancellationRequested();
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            {
                writer.Write(json);
                writer.Flush();
                stream.Flush(true);
            }

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryPath, targetPath);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static void EnsureCount(int count)
    {
        if (count > MaximumExportRecords)
        {
            throw new InvalidDataException("当前项目审计记录过多，请按项目拆分后导出。");
        }
    }
}

internal sealed class UnavailableEvidenceManifestExporter : IProjectEvidenceManifestExporter
{
    public Task<EvidenceManifestExportResult> ExportAsync(
        ProjectRecord project,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new InvalidOperationException("项目证据清单导出服务尚未初始化。");
    }
}

internal sealed class UnavailableEvidenceManifestExportFilePicker : IEvidenceManifestExportFilePicker
{
    public string? SelectDestination(ProjectRecord project) => null;
}
