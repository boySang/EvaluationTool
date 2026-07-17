using System;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Domain;

public sealed class DeviceIdentificationRecordTests
{
    [Fact]
    public void Record_round_trips_candidate_and_normalizes_time()
    {
        var recordedAt = new DateTimeOffset(2026, 7, 18, 9, 10, 11, TimeSpan.FromHours(8));
        var record = new DeviceIdentificationRecord(
            DeviceId.New(),
            1,
            TargetCategory.Server,
            "ubuntu",
            "Linux",
            "virtual-machine",
            "22.04",
            "ID=ubuntu",
            0.95,
            true,
            "测评人员人工确认",
            recordedAt);

        var candidate = record.ToCandidate();
        Assert.Equal(TargetCategory.Server, candidate.Category);
        Assert.Equal("ubuntu", candidate.Vendor);
        Assert.Equal("22.04", candidate.Version);
        Assert.True(record.WasUserConfirmed);
        Assert.Equal(TimeSpan.Zero, record.RecordedAt.Offset);
    }

    [Theory]
    [InlineData(true, null)]
    [InlineData(false, "不应存在的人工来源")]
    public void Record_rejects_inconsistent_confirmation_metadata(
        bool wasUserConfirmed,
        string? confirmationSource)
    {
        Assert.Throws<ArgumentException>(() => new DeviceIdentificationRecord(
            DeviceId.New(),
            1,
            TargetCategory.Server,
            "ubuntu",
            null,
            null,
            null,
            "ID=ubuntu",
            0.95,
            wasUserConfirmed,
            confirmationSource,
            DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Record_rejects_automatic_category_and_control_characters()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new DeviceIdentificationRecord(
            DeviceId.New(), 1, TargetCategory.Automatic, null, null, null, null,
            "fixture", 0.5, false, null, DateTimeOffset.UtcNow));
        Assert.Throws<ArgumentException>(() => new DeviceIdentificationRecord(
            DeviceId.New(), 1, TargetCategory.Server, "ubuntu\nforged", null, null, null,
            "fixture", 0.5, false, null, DateTimeOffset.UtcNow));
    }
}
