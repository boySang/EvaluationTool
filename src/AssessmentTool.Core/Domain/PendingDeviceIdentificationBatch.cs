using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace AssessmentTool.Core.Domain;

public enum PendingIdentificationResolution
{
    RevalidatedAndCompleted = 1,
    SupersededByNewDetection = 2,
    DismissedByUser = 3
}

public sealed class PendingDeviceIdentificationBatch
{
    public PendingDeviceIdentificationBatch(
        Guid batchId,
        DeviceId deviceId,
        long revision,
        IEnumerable<DetectionCandidate> candidates,
        DateTimeOffset recordedAt)
    {
        if (batchId == Guid.Empty)
        {
            throw new ArgumentException("识别候选批次标识不能为空。", nameof(batchId));
        }

        if (!deviceId.IsValid)
        {
            throw new ArgumentException("Device ID must be initialized.", nameof(deviceId));
        }

        if (revision < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(revision), revision, "候选批次修订号必须从一开始。");
        }

        if (candidates == null)
        {
            throw new ArgumentNullException(nameof(candidates));
        }

        var copiedCandidates = candidates.ToArray();
        if (copiedCandidates.Length == 0 || copiedCandidates.Length > 32)
        {
            throw new ArgumentException("识别候选批次必须包含 1 到 32 个候选项。", nameof(candidates));
        }

        if (copiedCandidates.Any(candidate => candidate == null
                || candidate.Category == TargetCategory.Automatic))
        {
            throw new ArgumentException("识别候选项必须完整并使用具体设备类别。", nameof(candidates));
        }

        if (recordedAt == default(DateTimeOffset))
        {
            throw new ArgumentException("识别候选批次时间不能为空。", nameof(recordedAt));
        }

        BatchId = batchId;
        DeviceId = deviceId;
        Revision = revision;
        Candidates = new ReadOnlyCollection<DetectionCandidate>(copiedCandidates);
        RecordedAt = recordedAt.ToUniversalTime();
    }

    public Guid BatchId { get; }
    public DeviceId DeviceId { get; }
    public long Revision { get; }
    public IReadOnlyList<DetectionCandidate> Candidates { get; }
    public DateTimeOffset RecordedAt { get; }
}
