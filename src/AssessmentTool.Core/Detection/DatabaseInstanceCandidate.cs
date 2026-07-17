using System;

namespace AssessmentTool.Core.Detection;

public enum DatabaseInstallationType
{
    LocalService,
    Container
}

public sealed class DatabaseInstanceCandidate
{
    internal DatabaseInstanceCandidate(
        string product,
        string? version,
        DatabaseInstallationType installationType,
        string instanceName,
        string? portEvidence,
        string evidence,
        double confidence,
        bool requiresUserConfirmation)
    {
        Product = Required(product, nameof(product));
        Version = Optional(version, nameof(version));
        if (!Enum.IsDefined(typeof(DatabaseInstallationType), installationType))
        {
            throw new ArgumentOutOfRangeException(nameof(installationType), installationType, "数据库安装方式无效。");
        }

        InstallationType = installationType;
        InstanceName = Required(instanceName, nameof(instanceName));
        PortEvidence = Optional(portEvidence, nameof(portEvidence));
        Evidence = Required(evidence, nameof(evidence));
        if (double.IsNaN(confidence) || double.IsInfinity(confidence) || confidence < 0 || confidence > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(confidence), confidence, "数据库识别可信度必须介于 0 和 1 之间。");
        }

        Confidence = confidence;
        RequiresUserConfirmation = requiresUserConfirmation;
    }

    public string Product { get; }
    public string? Version { get; }
    public DatabaseInstallationType InstallationType { get; }
    public string InstanceName { get; }
    public string? PortEvidence { get; }
    public string Evidence { get; }
    public double Confidence { get; }
    public bool RequiresUserConfirmation { get; }

    public DatabaseInstanceCandidate RequireConfirmation()
    {
        return RequiresUserConfirmation
            ? this
            : new DatabaseInstanceCandidate(
                Product,
                Version,
                InstallationType,
                InstanceName,
                PortEvidence,
                Evidence,
                Confidence,
                requiresUserConfirmation: true);
    }

    private static string Required(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("数据库候选字段不能为空。", parameterName);
        }

        if (ContainsControl(value))
        {
            throw new ArgumentException("数据库候选字段不能包含控制字符。", parameterName);
        }

        return value;
    }

    private static string? Optional(string? value, string parameterName)
    {
        if (value == null)
        {
            return null;
        }

        return Required(value, parameterName);
    }

    private static bool ContainsControl(string value)
    {
        foreach (var character in value)
        {
            if (char.IsControl(character))
            {
                return true;
            }
        }

        return false;
    }
}
