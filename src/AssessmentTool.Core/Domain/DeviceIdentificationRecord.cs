using System;

namespace AssessmentTool.Core.Domain;

public sealed class DeviceIdentificationRecord
{
    public DeviceIdentificationRecord(
        DeviceId deviceId,
        long revision,
        TargetCategory category,
        string? vendor,
        string? productFamily,
        string? model,
        string? version,
        string evidence,
        double confidence,
        bool wasUserConfirmed,
        string? confirmationSource,
        DateTimeOffset recordedAt)
    {
        if (!deviceId.IsValid)
        {
            throw new ArgumentException("Device ID must be initialized.", nameof(deviceId));
        }

        if (revision < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(revision), revision, "Revision must start at one.");
        }

        if (!Enum.IsDefined(typeof(TargetCategory), category) || category == TargetCategory.Automatic)
        {
            throw new ArgumentOutOfRangeException(nameof(category), category, "识别记录必须使用具体设备类别。");
        }

        if (double.IsNaN(confidence) || double.IsInfinity(confidence) || confidence < 0 || confidence > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(confidence), confidence, "识别可信度必须介于 0 和 1 之间。");
        }

        if (recordedAt == default(DateTimeOffset))
        {
            throw new ArgumentException("识别记录时间不能为空。", nameof(recordedAt));
        }

        DeviceId = deviceId;
        Revision = revision;
        Category = category;
        Vendor = Optional(vendor, nameof(vendor), 200);
        ProductFamily = Optional(productFamily, nameof(productFamily), 200);
        Model = Optional(model, nameof(model), 200);
        Version = Optional(version, nameof(version), 200);
        Evidence = Required(evidence, nameof(evidence), 4096);
        Confidence = confidence;
        WasUserConfirmed = wasUserConfirmed;
        ConfirmationSource = wasUserConfirmed
            ? Required(confirmationSource, nameof(confirmationSource), 500)
            : confirmationSource == null
                ? null
                : throw new ArgumentException("自动识别记录不能包含人工确认来源。", nameof(confirmationSource));
        RecordedAt = recordedAt.ToUniversalTime();
    }

    public DeviceId DeviceId { get; }
    public long Revision { get; }
    public TargetCategory Category { get; }
    public string? Vendor { get; }
    public string? ProductFamily { get; }
    public string? Model { get; }
    public string? Version { get; }
    public string Evidence { get; }
    public double Confidence { get; }
    public bool WasUserConfirmed { get; }
    public string? ConfirmationSource { get; }
    public DateTimeOffset RecordedAt { get; }

    public DetectionCandidate ToCandidate()
    {
        return new DetectionCandidate(
            Category,
            Vendor,
            ProductFamily,
            Model,
            Version,
            Evidence,
            Confidence);
    }

    private static string Required(string? value, string parameterName, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be blank.", parameterName);
        }

        if (value.Length > maximumLength)
        {
            throw new ArgumentException("Value exceeds the maximum supported length.", parameterName);
        }

        foreach (var character in value)
        {
            if (char.IsControl(character))
            {
                throw new ArgumentException("Value cannot contain control characters.", parameterName);
            }
        }

        return value;
    }

    private static string? Optional(string? value, string parameterName, int maximumLength)
    {
        return value == null ? null : Required(value, parameterName, maximumLength);
    }
}
