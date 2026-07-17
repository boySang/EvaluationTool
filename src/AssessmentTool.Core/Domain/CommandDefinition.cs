using System;

namespace AssessmentTool.Core.Domain;

public enum VerificationStatus
{
    Pending,
    Verified,
    Rejected
}

public enum CommandRiskLevel
{
    Low,
    Medium,
    High
}

public enum PagingBehavior
{
    NotApplicable,
    DisablePaging,
    HandlePagination
}

public sealed class CommandDefinition
{
    internal CommandDefinition(
        string id,
        string title,
        TargetCategory targetCategory,
        string commandText,
        VerificationStatus verificationStatus,
        bool isReadOnly,
        string? vendor,
        string? productFamily,
        string? minimumVersion,
        string? maximumVersion,
        string checkItem,
        string modelRange,
        string accountRequirement,
        CommandRiskLevel riskLevel,
        TimeSpan timeout,
        PagingBehavior pagingBehavior,
        string resultDescription,
        DateTime verificationDate,
        string officialSource,
        bool isOptional = false,
        string? alternativeGroup = null)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        Title = title ?? throw new ArgumentNullException(nameof(title));
        TargetCategory = targetCategory;
        CommandText = commandText ?? throw new ArgumentNullException(nameof(commandText));
        VerificationStatus = verificationStatus;
        IsReadOnly = isReadOnly;
        Vendor = vendor;
        ProductFamily = productFamily;
        MinimumVersion = minimumVersion;
        MaximumVersion = maximumVersion;
        CheckItem = checkItem ?? throw new ArgumentNullException(nameof(checkItem));
        ModelRange = modelRange ?? throw new ArgumentNullException(nameof(modelRange));
        AccountRequirement = accountRequirement ?? throw new ArgumentNullException(nameof(accountRequirement));
        RiskLevel = riskLevel;
        Timeout = timeout;
        PagingBehavior = pagingBehavior;
        ResultDescription = resultDescription ?? throw new ArgumentNullException(nameof(resultDescription));
        VerificationDate = verificationDate;
        OfficialSource = officialSource ?? throw new ArgumentNullException(nameof(officialSource));
        IsOptional = isOptional;
        AlternativeGroup = ValidateAlternativeGroup(alternativeGroup);
    }

    public string Id { get; }
    public string Title { get; }
    public TargetCategory TargetCategory { get; }
    public string CommandText { get; }
    public VerificationStatus VerificationStatus { get; }
    public bool IsReadOnly { get; }
    public string? Vendor { get; }
    public string? ProductFamily { get; }
    public string? MinimumVersion { get; }
    public string? MaximumVersion { get; }
    public string CheckItem { get; }
    public string ModelRange { get; }
    public string AccountRequirement { get; }
    public CommandRiskLevel RiskLevel { get; }
    public TimeSpan Timeout { get; }
    public PagingBehavior PagingBehavior { get; }
    public string ResultDescription { get; }
    public DateTime VerificationDate { get; }
    public string OfficialSource { get; }
    public bool IsOptional { get; }
    public string? AlternativeGroup { get; }
    public bool IsEligibleForAutomaticExecution => VerificationStatus == VerificationStatus.Verified && IsReadOnly;

    private static string? ValidateAlternativeGroup(string? value)
    {
        if (value == null)
        {
            return null;
        }

        var trimmed = value.Trim();
        if (trimmed.Length == 0)
        {
            throw new ArgumentException("替代命令组不能为空。", nameof(value));
        }

        if (trimmed.Length > 200)
        {
            throw new ArgumentException("替代命令组不能超过 200 个字符。", nameof(value));
        }

        foreach (var character in trimmed)
        {
            if (char.IsControl(character))
            {
                throw new ArgumentException("替代命令组不能包含控制字符。", nameof(value));
            }
        }

        return trimmed;
    }
}
