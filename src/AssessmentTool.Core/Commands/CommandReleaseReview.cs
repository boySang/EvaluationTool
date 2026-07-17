using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Security;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AssessmentTool.Core.Commands;

public sealed class CommandReleaseReviewRequest
{
    public CommandReleaseReviewRequest(
        string? packId,
        string? packName,
        string? packVersion,
        string? officialSource,
        string? reviewedBy,
        DateTimeOffset reviewedAt,
        IEnumerable<CommandReleaseReviewItem>? commands)
    {
        PackId = packId;
        PackName = packName;
        PackVersion = packVersion;
        OfficialSource = officialSource;
        ReviewedBy = reviewedBy;
        ReviewedAt = reviewedAt.ToUniversalTime();
        Commands = new ReadOnlyCollection<CommandReleaseReviewItem>(
            (commands ?? Array.Empty<CommandReleaseReviewItem>()).ToArray());
    }

    public string? PackId { get; }
    public string? PackName { get; }
    public string? PackVersion { get; }
    public string? OfficialSource { get; }
    public string? ReviewedBy { get; }
    public DateTimeOffset ReviewedAt { get; }
    public IReadOnlyList<CommandReleaseReviewItem> Commands { get; }
}

public sealed class CommandReleaseReviewItem
{
    public CommandReleaseReviewItem(
        int draftCommandIndex,
        string? vendor,
        string? productFamily,
        string? minimumVersion,
        string? maximumVersion,
        string? checkItem,
        string? modelRange,
        string? accountRequirement,
        CommandRiskLevel? riskLevel,
        int? timeoutSeconds,
        PagingBehavior? pagingBehavior,
        string? resultDescription,
        DateTime? verificationDate,
        string? officialSource,
        bool optional = false,
        string? alternativeGroup = null)
    {
        DraftCommandIndex = draftCommandIndex;
        Vendor = vendor;
        ProductFamily = productFamily;
        MinimumVersion = minimumVersion;
        MaximumVersion = maximumVersion;
        CheckItem = checkItem;
        ModelRange = modelRange;
        AccountRequirement = accountRequirement;
        RiskLevel = riskLevel;
        TimeoutSeconds = timeoutSeconds;
        PagingBehavior = pagingBehavior;
        ResultDescription = resultDescription;
        VerificationDate = verificationDate;
        OfficialSource = officialSource;
        Optional = optional;
        AlternativeGroup = alternativeGroup;
    }

    public int DraftCommandIndex { get; }
    public string? Vendor { get; }
    public string? ProductFamily { get; }
    public string? MinimumVersion { get; }
    public string? MaximumVersion { get; }
    public string? CheckItem { get; }
    public string? ModelRange { get; }
    public string? AccountRequirement { get; }
    public CommandRiskLevel? RiskLevel { get; }
    public int? TimeoutSeconds { get; }
    public PagingBehavior? PagingBehavior { get; }
    public string? ResultDescription { get; }
    public DateTime? VerificationDate { get; }
    public string? OfficialSource { get; }
    public bool Optional { get; }
    public string? AlternativeGroup { get; }
}

public sealed class CommandReleaseReviewFinding
{
    internal CommandReleaseReviewFinding(
        CommandDraftFindingSeverity severity,
        string code,
        string message,
        int? commandIndex)
    {
        Severity = severity;
        Code = code;
        Message = message;
        CommandIndex = commandIndex;
    }

    public CommandDraftFindingSeverity Severity { get; }
    public string Code { get; }
    public string Message { get; }
    public int? CommandIndex { get; }
}

public sealed class CommandReleaseCandidateCommand
{
    internal CommandReleaseCandidateCommand(CommandDefinition command)
    {
        Id = command.Id;
        Title = command.Title;
        TargetCategory = command.TargetCategory;
        CommandText = command.CommandText;
        Vendor = command.Vendor;
        ProductFamily = command.ProductFamily;
        MinimumVersion = command.MinimumVersion
            ?? throw new InvalidOperationException("发布候选命令缺少最低版本。");
        MaximumVersion = command.MaximumVersion
            ?? throw new InvalidOperationException("发布候选命令缺少最高版本。");
        CheckItem = command.CheckItem;
        ModelRange = command.ModelRange;
        AccountRequirement = command.AccountRequirement;
        RiskLevel = command.RiskLevel;
        Timeout = command.Timeout;
        PagingBehavior = command.PagingBehavior;
        ResultDescription = command.ResultDescription;
        VerificationDate = command.VerificationDate;
        OfficialSource = command.OfficialSource;
        Optional = command.IsOptional;
        AlternativeGroup = command.AlternativeGroup;
    }

    public string Id { get; }
    public string Title { get; }
    public TargetCategory TargetCategory { get; }
    public string CommandText { get; }
    public string? Vendor { get; }
    public string? ProductFamily { get; }
    public string MinimumVersion { get; }
    public string MaximumVersion { get; }
    public string CheckItem { get; }
    public string ModelRange { get; }
    public string AccountRequirement { get; }
    public CommandRiskLevel RiskLevel { get; }
    public TimeSpan Timeout { get; }
    public PagingBehavior PagingBehavior { get; }
    public string ResultDescription { get; }
    public DateTime VerificationDate { get; }
    public string OfficialSource { get; }
    public bool Optional { get; }
    public string? AlternativeGroup { get; }
}

public sealed class CommandReleaseCandidate
{
    internal CommandReleaseCandidate(
        string packId,
        string packName,
        string packVersion,
        string officialSource,
        string reviewedBy,
        DateTimeOffset reviewedAt,
        string canonicalJson,
        string canonicalSha256,
        IEnumerable<CommandDefinition> commands)
    {
        PackId = packId;
        PackName = packName;
        PackVersion = packVersion;
        OfficialSource = officialSource;
        ReviewedBy = reviewedBy;
        ReviewedAt = reviewedAt;
        CanonicalJson = canonicalJson;
        CanonicalSha256 = canonicalSha256;
        Commands = new ReadOnlyCollection<CommandReleaseCandidateCommand>(
            commands.Select(command => new CommandReleaseCandidateCommand(command)).ToArray());
    }

    public string PackId { get; }
    public string PackName { get; }
    public string PackVersion { get; }
    public string OfficialSource { get; }
    public string ReviewedBy { get; }
    public DateTimeOffset ReviewedAt { get; }
    public string CanonicalJson { get; }
    public string CanonicalSha256 { get; }
    public IReadOnlyList<CommandReleaseCandidateCommand> Commands { get; }
    public bool IsExecutable => false;
}

public sealed class CommandReleaseReviewResult
{
    internal CommandReleaseReviewResult(
        IEnumerable<CommandReleaseReviewFinding> findings,
        CommandReleaseCandidate? candidate)
    {
        Findings = new ReadOnlyCollection<CommandReleaseReviewFinding>(findings.ToArray());
        Candidate = candidate;
    }

    public IReadOnlyList<CommandReleaseReviewFinding> Findings { get; }
    public CommandReleaseCandidate? Candidate { get; }
    public bool HasBlockers => Findings.Any(finding => finding.Severity == CommandDraftFindingSeverity.Blocker);
    public bool IsPublishable => Candidate != null && !HasBlockers;
}

public sealed class CommandReleaseReviewer
{
    private readonly CommandSafetyPolicy safetyPolicy;

    public CommandReleaseReviewer()
        : this(new CommandSafetyPolicy())
    {
    }

    internal CommandReleaseReviewer(CommandSafetyPolicy safetyPolicy)
    {
        this.safetyPolicy = safetyPolicy ?? throw new ArgumentNullException(nameof(safetyPolicy));
    }

    public CommandReleaseReviewResult Review(
        CommandDraftImportResult draft,
        CommandReleaseReviewRequest request)
    {
        if (draft == null)
        {
            throw new ArgumentNullException(nameof(draft));
        }

        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        var findings = new List<CommandReleaseReviewFinding>();
        CopyDraftBlockers(draft, findings);

        var packId = Required(request.PackId, "PACK_ID_MISSING", "发布候选缺少命令包标识。", findings);
        var packName = Required(request.PackName, "PACK_NAME_MISSING", "发布候选缺少命令包名称。", findings);
        var packVersion = ValidatePackVersion(request.PackVersion, findings);
        var packSource = ValidateHttpsSource(request.OfficialSource, "PACK_SOURCE_MISSING", "PACK_SOURCE_INVALID", null, findings);
        var reviewedBy = Required(request.ReviewedBy, "REVIEWER_MISSING", "发布候选必须记录审核人。", findings);

        if (draft.Commands.Count == 0)
        {
            AddBlocker(findings, "COMMANDS_EMPTY", "没有可供审核的命令。", null);
        }

        var reviewedByIndex = IndexReviewItems(request.Commands, draft.Commands.Count, findings);
        var commands = new List<CommandDefinition>();
        var commandIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var draftCommand in draft.Commands)
        {
            if (!reviewedByIndex.TryGetValue(draftCommand.Index, out var review))
            {
                AddBlocker(findings, "COMMAND_REVIEW_MISSING", "命令缺少逐条审核元数据。", draftCommand.Index);
                continue;
            }

            var command = ReviewCommand(draftCommand, review, findings);
            if (command == null)
            {
                continue;
            }

            if (!commandIds.Add(command.Id))
            {
                AddBlocker(findings, "COMMAND_ID_DUPLICATE", "命令标识不能重复。", draftCommand.Index);
                continue;
            }

            var safety = safetyPolicy.Validate(command);
            if (!safety.Allowed)
            {
                AddBlocker(
                    findings,
                    "SAFETY_" + safety.Code.ToUpperInvariant().Replace('-', '_'),
                    "命令未通过只读白名单审查：" + safety.Message,
                    draftCommand.Index);
                continue;
            }

            commands.Add(command);
        }

        if (findings.Any(finding => finding.Severity == CommandDraftFindingSeverity.Blocker))
        {
            return new CommandReleaseReviewResult(findings, null);
        }

        var canonicalJson = BuildCanonicalJson(packId!, packName!, packVersion!, packSource!, commands);
        var canonicalSha256 = ComputeSha256(Encoding.UTF8.GetBytes(canonicalJson));
        try
        {
            new CommandPackLoader(safetyPolicy).Load(
                Encoding.UTF8.GetBytes(canonicalJson),
                canonicalSha256);
        }
        catch (CommandPackException exception)
        {
            AddBlocker(
                findings,
                "FORMAL_PACK_VALIDATION_FAILED",
                "发布候选未通过正式命令包结构复核：" + exception.Message,
                null);
            return new CommandReleaseReviewResult(findings, null);
        }

        var candidate = new CommandReleaseCandidate(
            packId!,
            packName!,
            packVersion!,
            packSource!,
            reviewedBy!,
            request.ReviewedAt,
            canonicalJson,
            canonicalSha256,
            commands);
        findings.Add(new CommandReleaseReviewFinding(
            CommandDraftFindingSeverity.Information,
            "RELEASE_CANDIDATE_CREATED",
            "全部命令已通过逐条只读审查，已生成不可执行的发布候选。",
            null));
        return new CommandReleaseReviewResult(findings, candidate);
    }

    private CommandDefinition? ReviewCommand(
        CommandDraftItem draft,
        CommandReleaseReviewItem review,
        ICollection<CommandReleaseReviewFinding> findings)
    {
        var initialBlockerCount = CountBlockers(findings);
        var id = Required(draft.Id, "COMMAND_ID_MISSING", "命令缺少标识。", findings, draft.Index);
        var title = Required(draft.Title, "COMMAND_TITLE_MISSING", "命令缺少标题。", findings, draft.Index);
        var commandText = Required(draft.CommandText, "COMMAND_TEXT_MISSING", "命令缺少文本。", findings, draft.Index);
        var targetCategory = ParseTargetCategory(draft.TargetCategory, draft.Index, findings);
        var minimumVersion = ValidateVersion(review.MinimumVersion, "MINIMUM_VERSION_MISSING", "MINIMUM_VERSION_INVALID", draft.Index, findings);
        var maximumVersion = ValidateVersion(review.MaximumVersion, "MAXIMUM_VERSION_MISSING", "MAXIMUM_VERSION_INVALID", draft.Index, findings);
        if (minimumVersion != null && maximumVersion != null && minimumVersion.CompareTo(maximumVersion) > 0)
        {
            AddBlocker(findings, "VERSION_RANGE_INVALID", "命令最低版本不能高于最高版本。", draft.Index);
        }

        var source = ValidateHttpsSource(review.OfficialSource, "COMMAND_SOURCE_MISSING", "COMMAND_SOURCE_INVALID", draft.Index, findings);
        var checkItem = Required(review.CheckItem, "CHECK_ITEM_MISSING", "命令缺少测评项。", findings, draft.Index);
        var modelRange = Required(review.ModelRange, "MODEL_RANGE_MISSING", "命令缺少型号范围。", findings, draft.Index);
        var accountRequirement = Required(review.AccountRequirement, "ACCOUNT_REQUIREMENT_MISSING", "命令缺少执行账户要求。", findings, draft.Index);
        var resultDescription = Required(review.ResultDescription, "RESULT_DESCRIPTION_MISSING", "命令缺少结果说明。", findings, draft.Index);

        if (!review.RiskLevel.HasValue)
        {
            AddBlocker(findings, "RISK_METADATA_MISSING", "命令缺少风险等级元数据。", draft.Index);
        }
        else if (review.RiskLevel.Value != CommandRiskLevel.Low)
        {
            AddBlocker(findings, "RISK_LEVEL_BLOCKED", "只有低风险命令可以生成发布候选。", draft.Index);
        }

        if (!review.TimeoutSeconds.HasValue || review.TimeoutSeconds.Value <= 0)
        {
            AddBlocker(findings, "TIMEOUT_MISSING", "命令必须设置大于零的超时时间。", draft.Index);
        }

        if (!review.PagingBehavior.HasValue)
        {
            AddBlocker(findings, "PAGING_METADATA_MISSING", "命令缺少分页处理元数据。", draft.Index);
        }

        if (!review.VerificationDate.HasValue)
        {
            AddBlocker(findings, "VERIFICATION_DATE_MISSING", "命令缺少验证日期。", draft.Index);
        }
        else if (review.VerificationDate.Value.Date > DateTime.UtcNow.Date)
        {
            AddBlocker(findings, "VERIFICATION_DATE_INVALID", "命令验证日期不能晚于当前日期。", draft.Index);
        }

        var vendor = Optional(review.Vendor);
        var productFamily = Optional(review.ProductFamily);
        var alternativeGroup = Optional(review.AlternativeGroup);
        if (CountBlockers(findings) != initialBlockerCount)
        {
            return null;
        }

        return new CommandDefinition(
            id!,
            title!,
            targetCategory!.Value,
            commandText!,
            VerificationStatus.Verified,
            true,
            vendor,
            productFamily,
            minimumVersion!.ToString(),
            maximumVersion!.ToString(),
            checkItem!,
            modelRange!,
            accountRequirement!,
            review.RiskLevel!.Value,
            TimeSpan.FromSeconds(review.TimeoutSeconds!.Value),
            review.PagingBehavior!.Value,
            resultDescription!,
            review.VerificationDate!.Value.Date,
            source!,
            review.Optional,
            alternativeGroup);
    }

    private static IDictionary<int, CommandReleaseReviewItem> IndexReviewItems(
        IEnumerable<CommandReleaseReviewItem> reviewItems,
        int draftCount,
        ICollection<CommandReleaseReviewFinding> findings)
    {
        var indexed = new Dictionary<int, CommandReleaseReviewItem>();
        foreach (var item in reviewItems)
        {
            if (item == null)
            {
                AddBlocker(findings, "COMMAND_REVIEW_NULL", "逐条审核项不能为空。", null);
                continue;
            }

            if (item.DraftCommandIndex < 0 || item.DraftCommandIndex >= draftCount)
            {
                AddBlocker(findings, "COMMAND_REVIEW_UNKNOWN", "审核项不属于当前草稿。", item.DraftCommandIndex);
                continue;
            }

            if (indexed.ContainsKey(item.DraftCommandIndex))
            {
                AddBlocker(findings, "COMMAND_REVIEW_DUPLICATE", "同一草稿命令只能提交一份审核元数据。", item.DraftCommandIndex);
                continue;
            }

            indexed.Add(item.DraftCommandIndex, item);
        }

        return indexed;
    }

    private static void CopyDraftBlockers(
        CommandDraftImportResult draft,
        ICollection<CommandReleaseReviewFinding> findings)
    {
        foreach (var finding in draft.Findings.Where(item => item.Severity == CommandDraftFindingSeverity.Blocker))
        {
            findings.Add(new CommandReleaseReviewFinding(
                CommandDraftFindingSeverity.Blocker,
                "DRAFT_" + finding.Code,
                "草稿导入阻断项尚未解决：" + finding.Message,
                finding.CommandIndex));
        }
    }

    private static TargetCategory? ParseTargetCategory(
        string? value,
        int commandIndex,
        ICollection<CommandReleaseReviewFinding> findings)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Enum.GetNames(typeof(TargetCategory)).Contains(value, StringComparer.Ordinal)
            || !Enum.TryParse(value, false, out TargetCategory category)
            || category == TargetCategory.Automatic)
        {
            AddBlocker(findings, "TARGET_CATEGORY_INVALID", "命令对象类别缺失、无效或仍为自动识别。", commandIndex);
            return null;
        }

        return category;
    }

    private static Version? ValidateVersion(
        string? value,
        string missingCode,
        string invalidCode,
        int commandIndex,
        ICollection<CommandReleaseReviewFinding> findings)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            AddBlocker(findings, missingCode, "命令必须明确填写最低和最高适用版本。", commandIndex);
            return null;
        }

        if (!Version.TryParse(value.Trim(), out var version))
        {
            AddBlocker(findings, invalidCode, "命令版本必须为由数字和点组成的版本号。", commandIndex);
            return null;
        }

        return version;
    }

    private static string? ValidatePackVersion(
        string? value,
        ICollection<CommandReleaseReviewFinding> findings)
    {
        var version = Required(value, "PACK_VERSION_MISSING", "发布候选缺少命令包版本。", findings);
        if (version == null)
        {
            return null;
        }

        var parts = version.Split('.');
        if (parts.Length != 3 || parts.Any(part => !IsCanonicalUnsignedInteger(part)))
        {
            AddBlocker(findings, "PACK_VERSION_INVALID", "命令包版本必须为严格的 major.minor.patch。", null);
            return null;
        }

        return version;
    }

    private static bool IsCanonicalUnsignedInteger(string value)
    {
        if (value.Length == 0 || (value.Length > 1 && value[0] == '0'))
        {
            return false;
        }

        return value.All(character => character >= '0' && character <= '9');
    }

    private static string? ValidateHttpsSource(
        string? value,
        string missingCode,
        string invalidCode,
        int? commandIndex,
        ICollection<CommandReleaseReviewFinding> findings)
    {
        var source = Required(value, missingCode, "必须记录可追溯的官方来源。", findings, commandIndex);
        if (source == null)
        {
            return null;
        }

        if (!Uri.TryCreate(source, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            AddBlocker(findings, invalidCode, "官方来源必须是绝对 HTTPS 地址。", commandIndex);
            return null;
        }

        return source;
    }

    private static string? Required(
        string? value,
        string code,
        string message,
        ICollection<CommandReleaseReviewFinding> findings,
        int? commandIndex = null)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            AddBlocker(findings, code, message, commandIndex);
            return null;
        }

        return value.Trim();
    }

    private static string? Optional(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static int CountBlockers(IEnumerable<CommandReleaseReviewFinding> findings)
    {
        return findings.Count(finding => finding.Severity == CommandDraftFindingSeverity.Blocker);
    }

    private static void AddBlocker(
        ICollection<CommandReleaseReviewFinding> findings,
        string code,
        string message,
        int? commandIndex)
    {
        findings.Add(new CommandReleaseReviewFinding(
            CommandDraftFindingSeverity.Blocker,
            code,
            message,
            commandIndex));
    }

    private static string BuildCanonicalJson(
        string packId,
        string packName,
        string packVersion,
        string officialSource,
        IEnumerable<CommandDefinition> commands)
    {
        var root = new JObject
        {
            ["id"] = packId,
            ["name"] = packName,
            ["version"] = packVersion,
            ["officialSource"] = officialSource
        };
        var commandArray = new JArray();
        foreach (var command in commands)
        {
            var item = new JObject
            {
                ["id"] = command.Id,
                ["title"] = command.Title,
                ["targetCategory"] = command.TargetCategory.ToString(),
                ["commandText"] = command.CommandText,
                ["verificationStatus"] = VerificationStatus.Verified.ToString(),
                ["isReadOnly"] = true,
                ["vendor"] = command.Vendor == null ? JValue.CreateNull() : new JValue(command.Vendor),
                ["productFamily"] = command.ProductFamily == null ? JValue.CreateNull() : new JValue(command.ProductFamily),
                ["minimumVersion"] = command.MinimumVersion,
                ["maximumVersion"] = command.MaximumVersion,
                ["checkItem"] = command.CheckItem,
                ["modelRange"] = command.ModelRange,
                ["accountRequirement"] = command.AccountRequirement,
                ["riskLevel"] = command.RiskLevel.ToString(),
                ["timeoutSeconds"] = Convert.ToInt32(command.Timeout.TotalSeconds),
                ["pagingBehavior"] = command.PagingBehavior.ToString(),
                ["resultDescription"] = command.ResultDescription,
                ["verificationDate"] = command.VerificationDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                ["officialSource"] = command.OfficialSource,
                ["optional"] = command.IsOptional
            };
            if (command.AlternativeGroup != null)
            {
                item["alternativeGroup"] = command.AlternativeGroup;
            }

            commandArray.Add(item);
        }

        root["commands"] = commandArray;
        return root.ToString(Formatting.None);
    }

    private static string ComputeSha256(byte[] bytes)
    {
        using (var sha256 = SHA256.Create())
        {
            var hash = sha256.ComputeHash(bytes);
            var builder = new StringBuilder(hash.Length * 2);
            foreach (var value in hash)
            {
                builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
            }

            return builder.ToString();
        }
    }
}

public static class CommandReleaseReviewRequestFactory
{
    public static CommandReleaseReviewRequest FromImportedMetadata(
        CommandDraftImportResult draft,
        string reviewedBy,
        DateTimeOffset reviewedAt)
    {
        if (draft == null)
        {
            throw new ArgumentNullException(nameof(draft));
        }

        JObject root;
        using (var stringReader = new System.IO.StringReader(draft.RawJson))
        using (var jsonReader = new JsonTextReader(stringReader))
        {
            root = JObject.Load(jsonReader, new JsonLoadSettings
            {
                DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error,
                CommentHandling = CommentHandling.Ignore
            });
        }

        var items = new List<CommandReleaseReviewItem>();
        var commands = root["commands"] as JArray;
        if (commands != null)
        {
            for (var index = 0; index < commands.Count; index++)
            {
                var item = commands[index] as JObject;
                items.Add(new CommandReleaseReviewItem(
                    index,
                    Text(item, "vendor"),
                    Text(item, "productFamily"),
                    Text(item, "minimumVersion"),
                    Text(item, "maximumVersion"),
                    Text(item, "checkItem"),
                    Text(item, "modelRange"),
                    Text(item, "accountRequirement"),
                    EnumValue<CommandRiskLevel>(item, "riskLevel"),
                    Integer(item, "timeoutSeconds"),
                    EnumValue<PagingBehavior>(item, "pagingBehavior"),
                    Text(item, "resultDescription"),
                    Date(item, "verificationDate"),
                    Text(item, "officialSource"),
                    Boolean(item, "optional") ?? false,
                    Text(item, "alternativeGroup")));
            }
        }

        return new CommandReleaseReviewRequest(
            Text(root, "id"),
            Text(root, "name"),
            Text(root, "version"),
            Text(root, "officialSource"),
            reviewedBy,
            reviewedAt,
            items);
    }

    private static string? Text(JObject? document, string propertyName)
    {
        var token = document?[propertyName];
        return token?.Type == JTokenType.String ? token.Value<string>() : null;
    }

    private static int? Integer(JObject? document, string propertyName)
    {
        var token = document?[propertyName];
        return token?.Type == JTokenType.Integer ? token.Value<int?>() : null;
    }

    private static bool? Boolean(JObject? document, string propertyName)
    {
        var token = document?[propertyName];
        return token?.Type == JTokenType.Boolean ? token.Value<bool?>() : null;
    }

    private static TEnum? EnumValue<TEnum>(JObject? document, string propertyName)
        where TEnum : struct
    {
        var value = Text(document, propertyName);
        return value != null
            && Enum.TryParse(value, false, out TEnum parsed)
            && Enum.IsDefined(typeof(TEnum), parsed)
                ? parsed
                : (TEnum?)null;
    }

    private static DateTime? Date(JObject? document, string propertyName)
    {
        var value = Text(document, propertyName);
        return DateTime.TryParseExact(
            value,
            "yyyy-MM-dd",
            CultureInfo.InvariantCulture,
            DateTimeStyles.None,
            out var parsed)
                ? parsed.Date
                : (DateTime?)null;
    }
}
