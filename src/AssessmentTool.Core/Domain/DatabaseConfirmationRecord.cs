using System;
using AssessmentTool.Core.Detection;

namespace AssessmentTool.Core.Domain;

public sealed class DatabaseConfirmationRecord
{
    public DatabaseConfirmationRecord(
        ProjectId projectId,
        DeviceId deviceId,
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
        if (!projectId.IsValid)
        {
            throw new ArgumentException("Project ID must be initialized.", nameof(projectId));
        }

        if (!deviceId.IsValid)
        {
            throw new ArgumentException("Device ID must be initialized.", nameof(deviceId));
        }

        if (!Enum.IsDefined(typeof(DatabaseInstallationType), installationType))
        {
            throw new ArgumentOutOfRangeException(nameof(installationType), installationType, "数据库安装方式无效。");
        }

        if (double.IsNaN(confidence) || double.IsInfinity(confidence) || confidence < 0 || confidence > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(confidence), confidence, "数据库识别可信度必须介于 0 和 1 之间。");
        }

        ProjectId = projectId;
        DeviceId = deviceId;
        Product = Required(product, nameof(product));
        Version = Optional(version, nameof(version));
        InstallationType = installationType;
        InstanceName = Required(instanceName, nameof(instanceName));
        PortEvidence = Optional(portEvidence, nameof(portEvidence));
        DetectionEvidence = Required(detectionEvidence, nameof(detectionEvidence));
        Confidence = confidence;
        ConfirmedAt = confirmedAt.ToUniversalTime();
        ConfirmationSource = Required(confirmationSource, nameof(confirmationSource));
    }

    public ProjectId ProjectId { get; }
    public DeviceId DeviceId { get; }
    public string Product { get; }
    public string? Version { get; }
    public DatabaseInstallationType InstallationType { get; }
    public string InstanceName { get; }
    public string? PortEvidence { get; }
    public string DetectionEvidence { get; }
    public double Confidence { get; }
    public DateTimeOffset ConfirmedAt { get; }
    public string ConfirmationSource { get; }

    private static string Required(string value, string parameterName)
    {
        if (value == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be blank.", parameterName);
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

    private static string? Optional(string? value, string parameterName)
    {
        return value == null ? null : Required(value, parameterName);
    }
}
