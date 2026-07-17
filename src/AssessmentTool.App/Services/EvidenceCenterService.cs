using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;

namespace AssessmentTool.App.Services;

public enum EvidenceShaStatus
{
    Complete,
    Missing,
    Mismatch,
    NotAvailable
}

public enum EvidenceCenterFailure
{
    InvalidProject,
    IndexUnavailable
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

        StartedAt = startedAt;
        CompletedAt = completedAt;
        ExecutionStatus = executionStatus;
        RawOutputPath = rawOutputPath;
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
    public string ScreenshotCountText => ScreenshotCount + " 张";

    public string ShaStatusText
    {
        get
        {
            switch (ShaStatus)
            {
                case EvidenceShaStatus.Complete:
                    return "索引完整";
                case EvidenceShaStatus.Missing:
                    return "索引缺失";
                case EvidenceShaStatus.Mismatch:
                    return "索引不一致";
                default:
                    return "暂无 SHA";
            }
        }
    }
}

public sealed class EvidenceCenterSnapshot
{
    public EvidenceCenterSnapshot(ProjectId projectId, IEnumerable<EvidenceCenterItem> items)
    {
        if (projectId.Equals(default(ProjectId)))
        {
            throw new ArgumentException("Project ID must be initialized.", nameof(projectId));
        }

        if (items == null)
        {
            throw new ArgumentNullException(nameof(items));
        }

        ProjectId = projectId;
        Items = new ReadOnlyCollection<EvidenceCenterItem>(items.ToArray());
    }

    public ProjectId ProjectId { get; }
    public IReadOnlyList<EvidenceCenterItem> Items { get; }
}

public interface IEvidenceCenterService
{
    Task<EvidenceCenterSnapshot> LoadAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default);
}

public sealed class EvidenceCenterService : IEvidenceCenterService
{
    private readonly IProjectRepository repository;

    public EvidenceCenterService(IProjectRepository repository)
    {
        this.repository = repository ?? throw new ArgumentNullException(nameof(repository));
    }

    public async Task<EvidenceCenterSnapshot> LoadAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default)
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
            cancellationToken.ThrowIfCancellationRequested();

            if (executions == null || evidenceFiles == null || devices == null)
            {
                throw new InvalidOperationException("Repository returned no evidence index result.");
            }

            var evidenceIndex = EvidenceIndex.Create(evidenceFiles);
            var deviceNames = devices.ToDictionary(
                device => device.Id.ToString(),
                device => device.DisplayName,
                StringComparer.OrdinalIgnoreCase);
            var items = executions
                .Select(execution => CreateItem(execution, evidenceIndex, deviceNames))
                .OrderByDescending(item => item.StartedAt)
                .ThenBy(item => item.DeviceId, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.CommandId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return new EvidenceCenterSnapshot(projectId, items);
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
                EvidenceCenterFailure.IndexUnavailable,
                "证据索引暂时无法读取。请确认本地项目数据库可用后重试。");
        }
    }

    private static EvidenceCenterItem CreateItem(
        ExecutionRecord execution,
        EvidenceIndex evidenceIndex,
        IReadOnlyDictionary<string, string> deviceNames)
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
            execution.EvidenceImagePaths.Count,
            EvaluateShaStatus(execution, evidenceIndex));
    }

    private static EvidenceShaStatus EvaluateShaStatus(
        ExecutionRecord execution,
        EvidenceIndex evidenceIndex)
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

        return missing ? EvidenceShaStatus.Missing : EvidenceShaStatus.Complete;
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
