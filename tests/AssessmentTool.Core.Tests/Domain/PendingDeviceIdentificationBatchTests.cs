using System;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Domain;

public sealed class PendingDeviceIdentificationBatchTests
{
    [Fact]
    public void Batch_defensively_copies_candidates_and_normalizes_time()
    {
        var candidates = new[]
        {
            new DetectionCandidate(
                TargetCategory.Server, "ubuntu", "Linux", null, "24.04", "ID=ubuntu", 0.75)
        };
        var recordedAt = new DateTimeOffset(2026, 7, 18, 8, 0, 0, TimeSpan.FromHours(8));

        var batch = new PendingDeviceIdentificationBatch(
            Guid.NewGuid(), DeviceId.New(), 1, candidates, recordedAt);

        candidates[0] = new DetectionCandidate(
            TargetCategory.Server, "changed", null, null, null, "changed", 0.5);
        Assert.Equal("ubuntu", batch.Candidates[0].Vendor);
        Assert.Equal(TimeSpan.Zero, batch.RecordedAt.Offset);
    }

    [Fact]
    public void Batch_rejects_empty_or_automatic_candidates()
    {
        Assert.Throws<ArgumentException>(() => new PendingDeviceIdentificationBatch(
            Guid.NewGuid(), DeviceId.New(), 1, Array.Empty<DetectionCandidate>(), DateTimeOffset.UtcNow));
        Assert.Throws<ArgumentException>(() => new PendingDeviceIdentificationBatch(
            Guid.NewGuid(),
            DeviceId.New(),
            1,
            new[]
            {
                new DetectionCandidate(
                    TargetCategory.Automatic, null, null, null, null, "unknown", 0.2)
            },
            DateTimeOffset.UtcNow));
    }
}
