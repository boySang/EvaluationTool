using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AssessmentTool.Core.Commands;

public enum CommandDraftFindingSeverity
{
    Information,
    Warning,
    Blocker
}

public sealed class CommandDraftFinding
{
    public CommandDraftFinding(
        CommandDraftFindingSeverity severity,
        string code,
        string message,
        int? commandIndex = null)
    {
        if (!Enum.IsDefined(typeof(CommandDraftFindingSeverity), severity))
        {
            throw new ArgumentOutOfRangeException(nameof(severity));
        }

        Severity = severity;
        Code = Required(code, nameof(code));
        Message = Required(message, nameof(message));
        if (commandIndex < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(commandIndex));
        }

        CommandIndex = commandIndex;
    }

    public CommandDraftFindingSeverity Severity { get; }
    public string Code { get; }
    public string Message { get; }
    public int? CommandIndex { get; }

    private static string Required(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("草稿校验发现不能为空。", parameterName);
        }

        return value.Trim();
    }
}

public sealed class CommandDraftItem
{
    public CommandDraftItem(
        int index,
        string? id,
        string? title,
        string? commandText,
        string? targetCategory,
        string? declaredRiskLevel)
    {
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        Index = index;
        Id = id;
        Title = title;
        CommandText = commandText;
        TargetCategory = targetCategory;
        DeclaredRiskLevel = declaredRiskLevel;
    }

    public int Index { get; }
    public string? Id { get; }
    public string? Title { get; }
    public string? CommandText { get; }
    public string? TargetCategory { get; }
    public string? DeclaredRiskLevel { get; }
    public bool IsExecutable => false;
}

public sealed class CommandDraftImportResult
{
    internal CommandDraftImportResult(
        string sourceFileName,
        string rawSha256,
        string rawJson,
        DateTimeOffset importedAt,
        IEnumerable<CommandDraftItem> commands,
        IEnumerable<CommandDraftFinding> findings)
    {
        SourceFileName = sourceFileName;
        RawSha256 = rawSha256;
        RawJson = rawJson;
        ImportedAt = importedAt;
        Commands = new ReadOnlyCollection<CommandDraftItem>(commands.ToArray());
        Findings = new ReadOnlyCollection<CommandDraftFinding>(findings.ToArray());
    }

    public string SourceFileName { get; }
    public string RawSha256 { get; }
    public string RawJson { get; }
    public DateTimeOffset ImportedAt { get; }
    public IReadOnlyList<CommandDraftItem> Commands { get; }
    public IReadOnlyList<CommandDraftFinding> Findings { get; }
    public bool IsPendingReview => true;
    public bool IsExecutable => false;
    public bool HasBlockers => Findings.Any(finding => finding.Severity == CommandDraftFindingSeverity.Blocker);
}

public sealed class CommandDraftImportException : Exception
{
    public CommandDraftImportException(string message)
        : base(message)
    {
    }

    public CommandDraftImportException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class CommandDraftImporter
{
    public const int MaximumImportBytes = 1024 * 1024;
    private const int MaximumCommands = 500;
    private const int MaximumFieldLength = 32768;

    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
    private static readonly Regex ObviousMutationPattern = new Regex(
        @"(?:^|[;&|]\s*)(?:rm|mv|cp|chmod|chown|kill|shutdown|reboot|touch|mkdir|tee|sed\s+-i|systemctl\s+(?:start|stop|restart|enable|disable)|service\s+\S+\s+(?:start|stop|restart)|docker\s+(?:run|start|stop|restart|rm)|kubectl\s+(?:apply|create|delete|edit|patch)|configure\s+terminal|write\s+memory|copy\s+running-config|reload)(?:\s|$)|(?:^|\s)(?:Set|New|Remove|Stop|Restart|Enable|Disable)-[A-Za-z]+|(?:^|[^>])>>?[^=]|\b(?:insert|update|delete|merge|alter|drop|truncate|create|grant|revoke|commit|rollback)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public CommandDraftImportResult Import(
        byte[] jsonBytes,
        string sourceFileName,
        DateTimeOffset importedAt)
    {
        if (jsonBytes == null)
        {
            throw new ArgumentNullException(nameof(jsonBytes));
        }

        if (jsonBytes.Length == 0)
        {
            throw new CommandDraftImportException("导入文件为空。请选择包含命令草稿的 JSON 文件。");
        }

        if (jsonBytes.Length > MaximumImportBytes)
        {
            throw new CommandDraftImportException("导入文件超过 1 MB 限制。请拆分后重新导入。");
        }

        var fileName = SafeFileName(sourceFileName);
        var rawSha256 = ComputeSha256(jsonBytes);
        var json = Decode(jsonBytes);
        JObject root;
        try
        {
            using (var stringReader = new StringReader(json))
            using (var jsonReader = new JsonTextReader(stringReader))
            {
                root = JObject.Load(jsonReader, new JsonLoadSettings
                {
                    DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error,
                    CommentHandling = CommentHandling.Ignore,
                    LineInfoHandling = LineInfoHandling.Load
                });
                if (jsonReader.Read())
                {
                    throw new CommandDraftImportException("JSON 文件只能包含一个根对象。");
                }
            }
        }
        catch (CommandDraftImportException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new CommandDraftImportException("JSON 格式无效或包含重复字段。", exception);
        }

        var findings = new List<CommandDraftFinding>
        {
            new CommandDraftFinding(
                CommandDraftFindingSeverity.Information,
                "DRAFT_NEVER_EXECUTABLE",
                "导入内容已强制标记为待校验草稿，不能进入自动执行链路。")
        };
        AddRootFindings(root, findings);

        var commandsToken = root["commands"];
        var commands = new List<CommandDraftItem>();
        if (!(commandsToken is JArray commandArray))
        {
            findings.Add(new CommandDraftFinding(
                CommandDraftFindingSeverity.Blocker,
                "COMMANDS_MISSING",
                "根对象必须包含 commands 数组。"));
        }
        else if (commandArray.Count == 0)
        {
            findings.Add(new CommandDraftFinding(
                CommandDraftFindingSeverity.Blocker,
                "COMMANDS_EMPTY",
                "commands 数组至少需要一项。"));
        }
        else if (commandArray.Count > MaximumCommands)
        {
            findings.Add(new CommandDraftFinding(
                CommandDraftFindingSeverity.Blocker,
                "COMMAND_LIMIT_EXCEEDED",
                "单个草稿最多允许 500 条命令，请拆分文件。"));
        }

        if (commandsToken is JArray array)
        {
            for (var index = 0; index < Math.Min(array.Count, MaximumCommands); index++)
            {
                ParseCommand(array[index], index, commands, findings);
            }
        }

        return new CommandDraftImportResult(
            fileName,
            rawSha256,
            json,
            importedAt.ToUniversalTime(),
            commands,
            findings);
    }

    private static void ParseCommand(
        JToken token,
        int index,
        ICollection<CommandDraftItem> commands,
        ICollection<CommandDraftFinding> findings)
    {
        if (!(token is JObject item))
        {
            findings.Add(new CommandDraftFinding(
                CommandDraftFindingSeverity.Blocker,
                "COMMAND_NOT_OBJECT",
                "命令项必须是 JSON 对象。",
                index));
            return;
        }

        var id = ReadText(item, "id", index, findings);
        var title = ReadText(item, "title", index, findings);
        var commandText = ReadText(item, "commandText", index, findings);
        var targetCategory = ReadText(item, "targetCategory", index, findings);
        var riskLevel = ReadText(item, "riskLevel", index, findings);
        commands.Add(new CommandDraftItem(index, id, title, commandText, targetCategory, riskLevel));

        if (string.IsNullOrWhiteSpace(id))
        {
            AddBlocker(findings, "COMMAND_ID_MISSING", "命令缺少 id。", index);
        }

        if (string.IsNullOrWhiteSpace(title))
        {
            AddBlocker(findings, "COMMAND_TITLE_MISSING", "命令缺少 title。", index);
        }

        if (string.IsNullOrWhiteSpace(commandText))
        {
            AddBlocker(findings, "COMMAND_TEXT_MISSING", "命令缺少 commandText。", index);
        }
        else if (ObviousMutationPattern.IsMatch(commandText))
        {
            AddBlocker(findings, "OBVIOUS_MUTATION", "检测到明显修改或破坏性语句，禁止发布。", index);
        }

        var declaredVerification = ReadText(item, "verificationStatus", index, findings);
        if (!string.IsNullOrWhiteSpace(declaredVerification))
        {
            findings.Add(new CommandDraftFinding(
                CommandDraftFindingSeverity.Warning,
                "DECLARED_VERIFICATION_IGNORED",
                "文件声明的验证状态不受信任，已强制重置为待校验。",
                index));
        }

        if (item.Property("isReadOnly") != null)
        {
            findings.Add(new CommandDraftFinding(
                CommandDraftFindingSeverity.Warning,
                "DECLARED_READ_ONLY_IGNORED",
                "文件声明的只读标记不受信任，必须重新审查。",
                index));
        }

        if (string.Equals(riskLevel, "Medium", StringComparison.OrdinalIgnoreCase)
            || string.Equals(riskLevel, "High", StringComparison.OrdinalIgnoreCase))
        {
            AddBlocker(findings, "DECLARED_RISK_BLOCKED", "中高风险命令不能进入自动命令库。", index);
        }
    }

    private static string? ReadText(
        JObject item,
        string propertyName,
        int index,
        ICollection<CommandDraftFinding> findings)
    {
        var token = item[propertyName];
        if (token == null || token.Type == JTokenType.Null)
        {
            return null;
        }

        if (token.Type != JTokenType.String)
        {
            AddBlocker(findings, "INVALID_FIELD_TYPE", propertyName + " 必须是字符串。", index);
            return null;
        }

        var value = token.Value<string>();
        if (value != null && value.Length > MaximumFieldLength)
        {
            AddBlocker(findings, "FIELD_TOO_LONG", propertyName + " 超过允许长度。", index);
            return value.Substring(0, MaximumFieldLength);
        }

        return value;
    }

    private static void AddRootFindings(JObject root, ICollection<CommandDraftFinding> findings)
    {
        foreach (var required in new[] { "id", "name", "version" })
        {
            if (root[required]?.Type != JTokenType.String
                || string.IsNullOrWhiteSpace(root[required]?.Value<string>()))
            {
                findings.Add(new CommandDraftFinding(
                    CommandDraftFindingSeverity.Blocker,
                    "PACK_FIELD_MISSING",
                    "命令草稿缺少根字段 " + required + "。"));
            }
        }
    }

    private static void AddBlocker(
        ICollection<CommandDraftFinding> findings,
        string code,
        string message,
        int index)
    {
        findings.Add(new CommandDraftFinding(CommandDraftFindingSeverity.Blocker, code, message, index));
    }

    private static string Decode(byte[] bytes)
    {
        var offset = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? 3 : 0;
        try
        {
            return StrictUtf8.GetString(bytes, offset, bytes.Length - offset);
        }
        catch (DecoderFallbackException exception)
        {
            throw new CommandDraftImportException("导入文件必须使用有效的 UTF-8 编码。", exception);
        }
    }

    private static string SafeFileName(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("导入文件名不能为空。", nameof(value));
        }

        var fileName = Path.GetFileName(value.Trim().Replace('\\', '/'));
        if (string.IsNullOrWhiteSpace(fileName) || fileName.Any(char.IsControl))
        {
            throw new ArgumentException("导入文件名无效。", nameof(value));
        }

        return fileName;
    }

    private static string ComputeSha256(byte[] bytes)
    {
        using (var sha256 = SHA256.Create())
        {
            return string.Concat(sha256.ComputeHash(bytes).Select(value => value.ToString("x2")));
        }
    }
}
