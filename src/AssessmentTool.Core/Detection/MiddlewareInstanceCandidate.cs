using System;

namespace AssessmentTool.Core.Detection;

public enum MiddlewareInstallationType
{
    LocalService,
    Container
}

public sealed class MiddlewareInstanceCandidate
{
    internal MiddlewareInstanceCandidate(
        string product,
        string? version,
        MiddlewareInstallationType installationType,
        string instanceName,
        string? portEvidence,
        string evidence,
        double confidence)
    {
        Product = Required(product, nameof(product));
        Version = Optional(version, nameof(version));
        if (!Enum.IsDefined(typeof(MiddlewareInstallationType), installationType))
        {
            throw new ArgumentOutOfRangeException(nameof(installationType), installationType, "中间件安装方式无效。");
        }

        InstallationType = installationType;
        InstanceName = Required(instanceName, nameof(instanceName));
        PortEvidence = Optional(portEvidence, nameof(portEvidence));
        Evidence = Required(evidence, nameof(evidence));
        if (double.IsNaN(confidence) || double.IsInfinity(confidence) || confidence < 0 || confidence > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(confidence), confidence, "中间件识别可信度必须介于 0 和 1 之间。");
        }

        Confidence = confidence;
    }

    public string Product { get; }
    public string? Version { get; }
    public MiddlewareInstallationType InstallationType { get; }
    public string InstanceName { get; }
    public string? PortEvidence { get; }
    public string Evidence { get; }
    public double Confidence { get; }
    public bool RequiresUserConfirmation => true;

    private static string Required(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("中间件候选字段不能为空。", parameterName);
        }

        foreach (var character in value)
        {
            if (char.IsControl(character))
            {
                throw new ArgumentException("中间件候选字段不能包含控制字符。", parameterName);
            }
        }

        return value;
    }

    private static string? Optional(string? value, string parameterName)
    {
        return value == null ? null : Required(value, parameterName);
    }
}
