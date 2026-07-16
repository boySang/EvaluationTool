using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Security;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AssessmentTool.Core.Commands;

public sealed class CommandPackLoader
{
    private const string TestFixtureSource = "urn:assessment-tool:test-fixture";
    private const string TestFixtureVendor = "AssessmentTool.TestFixture";

    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private static readonly Regex StrictSemVerCore = new Regex(
        @"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$",
        RegexOptions.CultureInvariant);

    private static readonly JsonSerializerSettings SerializerSettings = new JsonSerializerSettings
    {
        MissingMemberHandling = MissingMemberHandling.Error
    };

    private static readonly ISet<string> PackPropertyNames = new HashSet<string>(StringComparer.Ordinal)
    {
        "id",
        "name",
        "version",
        "officialSource",
        "commands"
    };

    private static readonly ISet<string> CommandPropertyNames = new HashSet<string>(StringComparer.Ordinal)
    {
        "id",
        "title",
        "targetCategory",
        "commandText",
        "verificationStatus",
        "isReadOnly",
        "vendor",
        "productFamily",
        "minimumVersion",
        "maximumVersion",
        "checkItem",
        "modelRange",
        "accountRequirement",
        "riskLevel",
        "timeoutSeconds",
        "pagingBehavior",
        "resultDescription",
        "verificationDate",
        "officialSource"
    };

    private static readonly string[] RequiredPackStringProperties =
    {
        "id",
        "name",
        "version",
        "officialSource"
    };

    private static readonly string[] RequiredCommandStringProperties =
    {
        "id",
        "title",
        "targetCategory",
        "commandText",
        "verificationStatus",
        "checkItem",
        "modelRange",
        "accountRequirement",
        "riskLevel",
        "pagingBehavior",
        "resultDescription",
        "verificationDate",
        "officialSource"
    };

    private static readonly string[] NullableCommandStringProperties =
    {
        "vendor",
        "productFamily",
        "minimumVersion",
        "maximumVersion"
    };

    private readonly CommandSafetyPolicy safetyPolicy;

    public CommandPackLoader()
        : this(new CommandSafetyPolicy())
    {
    }

    internal CommandPackLoader(CommandSafetyPolicy safetyPolicy)
    {
        this.safetyPolicy = safetyPolicy ?? throw new ArgumentNullException(nameof(safetyPolicy));
    }

    public CommandPack Load(byte[] jsonBytes, string expectedSha256)
    {
        if (jsonBytes == null)
        {
            throw new CommandPackException("命令包 JSON 字节不能为空。");
        }

        var jsonSnapshot = CaptureInputSnapshot(jsonBytes);

        if (!IsSha256(expectedSha256))
        {
            throw new CommandPackException("受信任调用方必须提供格式正确的 SHA-256 值。");
        }

        var actualSha256 = ComputeSha256(jsonSnapshot);
        if (!HashesEqual(actualSha256, expectedSha256))
        {
            throw new CommandPackException("命令包 SHA-256 与受信任调用方提供的值不匹配。");
        }

        if (HasUtf8Bom(jsonSnapshot))
        {
            throw new CommandPackException("规范命令包不得包含 UTF-8 BOM。");
        }

        string json;
        try
        {
            json = StrictUtf8.GetString(jsonSnapshot);
        }
        catch (DecoderFallbackException exception)
        {
            throw new CommandPackException("命令包必须使用有效的 UTF-8 编码。", exception);
        }

        EnsureNoDuplicateProperties(json);
        var tokenTree = ParseAndValidateTokenTree(json);

        PackDocument document;
        try
        {
            document = tokenTree.ToObject<PackDocument>(JsonSerializer.Create(SerializerSettings))
                ?? throw new CommandPackException("命令包 JSON 不能为空对象。");
        }
        catch (CommandPackException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new CommandPackException("命令包包含未知或无效 JSON 字段。", exception);
        }

        var id = RequiredText(document.Id, "命令包标识");
        var name = RequiredText(document.Name, "命令包名称");
        var version = ValidatePackVersion(document.Version);
        var officialSource = ValidateOfficialSource(document.OfficialSource);
        if (document.Commands == null || document.Commands.Count == 0)
        {
            throw new CommandPackException("命令包至少需要包含一条命令。");
        }

        var commandIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var commands = new List<CommandDefinition>(document.Commands.Count);
        foreach (var commandDocument in document.Commands)
        {
            var command = CreateCommand(commandDocument);
            if (!commandIds.Add(command.Id))
            {
                throw new CommandPackException("命令包不能包含重复的命令标识。");
            }

            if (command.VerificationStatus != VerificationStatus.Verified)
            {
                throw new CommandPackException("正式命令包只能包含已验证命令。");
            }

            if (!command.IsReadOnly)
            {
                throw new CommandPackException("正式命令包只能包含只读命令。");
            }

            var decision = safetyPolicy.Validate(command);
            if (!decision.Allowed)
            {
                throw new CommandPackException("命令未通过只读安全策略：" + decision.Message);
            }

            commands.Add(command);
        }

        var isTestFixturePackage = string.Equals(officialSource, TestFixtureSource, StringComparison.Ordinal);
        if (isTestFixturePackage
            && commands.Any(command => !IsCanonicalTestFixtureVendor(command.Vendor)))
        {
            throw new CommandPackException("保留测试来源的命令包只能包含 AssessmentTool.TestFixture 命令。");
        }

        if (!isTestFixturePackage
            && commands.Any(command => IsReservedTestFixtureVendor(command.Vendor)))
        {
            throw new CommandPackException("AssessmentTool.TestFixture 命令只能包含在保留测试来源的命令包中。");
        }

        return new CommandPack(id, name, version, officialSource, actualSha256, commands);
    }

    internal static byte[] CaptureInputSnapshot(byte[] jsonBytes)
    {
        return jsonBytes.ToArray();
    }

    private static CommandDefinition CreateCommand(CommandDocument document)
    {
        if (document == null)
        {
            throw new CommandPackException("命令定义不能为空。");
        }

        var targetCategory = ParseEnum<TargetCategory>(document.TargetCategory, "对象类别");
        if (targetCategory == TargetCategory.Automatic)
        {
            throw new CommandPackException("命令定义不能使用自动识别对象类别。");
        }

        var verificationStatus = ParseEnum<VerificationStatus>(document.VerificationStatus, "验证状态");
        var riskLevel = ParseEnum<CommandRiskLevel>(document.RiskLevel, "风险等级");
        var pagingBehavior = ParseEnum<PagingBehavior>(document.PagingBehavior, "分页处理方式");
        var vendor = ValidateVendor(document.Vendor);
        var minimumVersion = OptionalVersion(document.MinimumVersion, "最低版本");
        var maximumVersion = OptionalVersion(document.MaximumVersion, "最高版本");
        if (minimumVersion != null && maximumVersion != null && minimumVersion.CompareTo(maximumVersion) > 0)
        {
            throw new CommandPackException("命令版本范围无效。");
        }

        if (document.TimeoutSeconds <= 0)
        {
            throw new CommandPackException("命令超时时间必须大于零。");
        }

        return new CommandDefinition(
            RequiredText(document.Id, "命令标识"),
            RequiredText(document.Title, "命令标题"),
            targetCategory,
            RequiredText(document.CommandText, "命令文本"),
            verificationStatus,
            document.IsReadOnly,
            vendor,
            OptionalText(document.ProductFamily, "产品系列"),
            document.MinimumVersion == null ? null : minimumVersion!.ToString(),
            document.MaximumVersion == null ? null : maximumVersion!.ToString(),
            RequiredText(document.CheckItem, "测评项"),
            ValidateModelRange(document.ModelRange),
            RequiredText(document.AccountRequirement, "执行账户要求"),
            riskLevel,
            TimeSpan.FromSeconds(document.TimeoutSeconds),
            pagingBehavior,
            RequiredText(document.ResultDescription, "结果说明"),
            ValidateVerificationDate(document.VerificationDate),
            ValidateCommandOfficialSource(document.OfficialSource, vendor));
    }

    private static string ValidateModelRange(string? value)
    {
        var modelRange = RequiredText(value, "型号范围");
        var wildcardIndex = modelRange.IndexOf('*');
        if (wildcardIndex < 0 || modelRange == "*")
        {
            return modelRange;
        }

        if (wildcardIndex != modelRange.Length - 1
            || modelRange.LastIndexOf('*') != wildcardIndex)
        {
            throw new CommandPackException("型号范围只允许 *、精确型号或末尾单个通配符。");
        }

        return modelRange;
    }

    private static DateTime ValidateVerificationDate(string? value)
    {
        if (value == null
            || !DateTime.TryParseExact(
                value,
                "yyyy-MM-dd",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out var verificationDate))
        {
            throw new CommandPackException("命令验证日期必须使用 ISO yyyy-MM-dd 格式。");
        }

        if (verificationDate > DateTime.UtcNow.Date)
        {
            throw new CommandPackException("命令验证日期不能晚于当前日期。");
        }

        return verificationDate;
    }

    private static string ValidateCommandOfficialSource(string? officialSource, string? vendor)
    {
        var source = RequiredText(officialSource, "命令官方来源");
        if (string.Equals(source, TestFixtureSource, StringComparison.Ordinal))
        {
            if (!IsCanonicalTestFixtureVendor(vendor))
            {
                throw new CommandPackException("保留测试来源只能用于 " + TestFixtureVendor + " 命令。");
            }

            return source;
        }

        if (!Uri.TryCreate(source, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new CommandPackException("命令官方来源必须使用 HTTPS，测试夹具只能使用保留来源。");
        }

        return source;
    }

    private static string? ValidateVendor(string? value)
    {
        var vendor = OptionalText(value, "厂商");
        if (IsReservedTestFixtureVendor(vendor) && !IsCanonicalTestFixtureVendor(vendor))
        {
            throw new CommandPackException("保留测试厂商必须使用规范拼写 " + TestFixtureVendor + "。");
        }

        return vendor;
    }

    private static bool IsReservedTestFixtureVendor(string? vendor)
    {
        return string.Equals(vendor, TestFixtureVendor, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCanonicalTestFixtureVendor(string? vendor)
    {
        return string.Equals(vendor, TestFixtureVendor, StringComparison.Ordinal);
    }

    private static string ValidateOfficialSource(string? officialSource)
    {
        var source = RequiredText(officialSource, "官方来源");
        if (string.Equals(source, TestFixtureSource, StringComparison.Ordinal))
        {
            return source;
        }

        if (!Uri.TryCreate(source, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new CommandPackException("官方来源必须使用 HTTPS，测试夹具只能使用保留来源。 ");
        }

        return source;
    }

    private static TEnum ParseEnum<TEnum>(string? value, string fieldName)
        where TEnum : struct
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Enum.GetNames(typeof(TEnum)).Contains(value, StringComparer.Ordinal))
        {
            throw new CommandPackException(fieldName + "无效。");
        }

        return (TEnum)Enum.Parse(typeof(TEnum), value, ignoreCase: false);
    }

    private static string ValidatePackVersion(string? value)
    {
        if (value == null || !StrictSemVerCore.IsMatch(value))
        {
            throw new CommandPackException("命令包版本必须为严格的 SemVer 核心版本 major.minor.patch。");
        }

        return value;
    }

    private static Version? OptionalVersion(string? value, string fieldName)
    {
        if (value == null)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(value) || !Version.TryParse(value, out var version))
        {
            throw new CommandPackException(fieldName + "必须为由数字和点组成的版本号。");
        }

        return version;
    }

    private static string? OptionalText(string? value, string fieldName)
    {
        if (value == null)
        {
            return null;
        }

        return RequiredText(value, fieldName);
    }

    private static string RequiredText(string? value, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new CommandPackException(fieldName + "不能为空。");
        }

        return value!.Trim();
    }

    private static void EnsureNoDuplicateProperties(string json)
    {
        try
        {
            using var stringReader = new StringReader(json);
            using var reader = new JsonTextReader(stringReader)
            {
                DateParseHandling = DateParseHandling.None
            };

            if (!reader.Read() || reader.TokenType != JsonToken.StartObject)
            {
                throw new CommandPackException("命令包 JSON 必须是对象。");
            }

            ValidateJsonValue(reader);
            if (reader.Read())
            {
                throw new CommandPackException("命令包 JSON 只能包含一个对象。");
            }
        }
        catch (CommandPackException)
        {
            throw;
        }
        catch (JsonException exception)
        {
            throw new CommandPackException("命令包 JSON 格式无效。", exception);
        }
    }

    private static JToken ParseAndValidateTokenTree(string json)
    {
        JToken token;
        try
        {
            using var stringReader = new StringReader(json);
            using var reader = new JsonTextReader(stringReader)
            {
                DateParseHandling = DateParseHandling.None
            };

            token = JToken.Load(reader);
        }
        catch (JsonException exception)
        {
            throw new CommandPackException("命令包 JSON 格式无效。", exception);
        }

        if (!(token is JObject packageObject))
        {
            throw new CommandPackException("命令包 JSON 必须是对象。");
        }

        ValidateObjectProperties(packageObject, PackPropertyNames, "命令包");
        ValidateRequiredStringProperties(packageObject, RequiredPackStringProperties, "命令包");
        var commands = GetRequiredProperty(packageObject, "commands", "命令包");
        ValidateTokenType(commands, JTokenType.Array, "命令包", "commands");

        foreach (var command in commands.Children())
        {
            if (!(command is JObject commandObject))
            {
                throw new CommandPackException("命令定义 JSON 类型必须为 Object。");
            }

            ValidateObjectProperties(commandObject, CommandPropertyNames, "命令定义");
            ValidateRequiredStringProperties(commandObject, RequiredCommandStringProperties, "命令定义");
            ValidateTokenType(GetRequiredProperty(commandObject, "isReadOnly", "命令定义"), JTokenType.Boolean, "命令定义", "isReadOnly");
            ValidateTokenType(GetRequiredProperty(commandObject, "timeoutSeconds", "命令定义"), JTokenType.Integer, "命令定义", "timeoutSeconds");
            ValidateNullableStringProperties(commandObject, NullableCommandStringProperties, "命令定义");
        }

        return token;
    }

    private static void ValidateObjectProperties(JObject value, ISet<string> allowedPropertyNames, string objectName)
    {
        foreach (var property in value.Properties())
        {
            if (!allowedPropertyNames.Contains(property.Name))
            {
                throw new CommandPackException(objectName + "包含未知字段：" + property.Name + "。");
            }
        }
    }

    private static void ValidateRequiredStringProperties(JObject value, IEnumerable<string> propertyNames, string objectName)
    {
        foreach (var propertyName in propertyNames)
        {
            ValidateTokenType(GetRequiredProperty(value, propertyName, objectName), JTokenType.String, objectName, propertyName);
        }
    }

    private static void ValidateNullableStringProperties(JObject value, IEnumerable<string> propertyNames, string objectName)
    {
        foreach (var propertyName in propertyNames)
        {
            var token = GetRequiredProperty(value, propertyName, objectName);
            if (token.Type != JTokenType.String && token.Type != JTokenType.Null)
            {
                throw new CommandPackException(objectName + "字段 " + propertyName + " JSON 类型必须为 String 或 Null。");
            }
        }
    }

    private static JToken GetRequiredProperty(JObject value, string propertyName, string objectName)
    {
        var property = value.Property(propertyName, StringComparison.Ordinal);
        if (property == null)
        {
            throw new CommandPackException(objectName + "缺少必填字段：" + propertyName + "。");
        }

        return property.Value;
    }

    private static void ValidateTokenType(JToken value, JTokenType expectedType, string objectName, string propertyName)
    {
        if (value.Type != expectedType)
        {
            throw new CommandPackException(objectName + "字段 " + propertyName + " JSON 类型必须为 " + expectedType + "。");
        }
    }

    private static void ValidateJsonValue(JsonTextReader reader)
    {
        if (reader.TokenType == JsonToken.StartObject)
        {
            var propertyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (reader.Read())
            {
                if (reader.TokenType == JsonToken.EndObject)
                {
                    return;
                }

                if (reader.TokenType != JsonToken.PropertyName || !(reader.Value is string propertyName))
                {
                    throw new CommandPackException("命令包 JSON 对象格式无效。");
                }

                if (!propertyNames.Add(propertyName))
                {
                    throw new CommandPackException("命令包 JSON 包含重复字段。");
                }

                if (!reader.Read())
                {
                    throw new CommandPackException("命令包 JSON 不完整。");
                }

                ValidateJsonValue(reader);
            }

            throw new CommandPackException("命令包 JSON 不完整。");
        }

        if (reader.TokenType == JsonToken.StartArray)
        {
            while (reader.Read())
            {
                if (reader.TokenType == JsonToken.EndArray)
                {
                    return;
                }

                ValidateJsonValue(reader);
            }

            throw new CommandPackException("命令包 JSON 不完整。");
        }
    }

    private static string ComputeSha256(byte[] jsonBytes)
    {
        using var algorithm = SHA256.Create();
        var hash = algorithm.ComputeHash(jsonBytes);
        var builder = new StringBuilder(hash.Length * 2);
        foreach (var value in hash)
        {
            builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }

    private static bool HasUtf8Bom(byte[] jsonBytes)
    {
        var preamble = Encoding.UTF8.GetPreamble();
        return jsonBytes.Length >= preamble.Length
            && jsonBytes.Take(preamble.Length).SequenceEqual(preamble);
    }

    private static bool IsSha256(string? value)
    {
        if (value == null || value.Length != 64)
        {
            return false;
        }

        return value.All(character => (character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'f')
            || (character >= 'A' && character <= 'F'));
    }

    private static bool HashesEqual(string actual, string expected)
    {
        var difference = 0;
        for (var index = 0; index < actual.Length; index++)
        {
            difference |= char.ToUpperInvariant(actual[index]) ^ char.ToUpperInvariant(expected[index]);
        }

        return difference == 0;
    }

    private sealed class PackDocument
    {
        [JsonProperty("id", Required = Required.Always)]
        public string? Id { get; set; }

        [JsonProperty("name", Required = Required.Always)]
        public string? Name { get; set; }

        [JsonProperty("version", Required = Required.Always)]
        public string? Version { get; set; }

        [JsonProperty("officialSource", Required = Required.Always)]
        public string? OfficialSource { get; set; }

        [JsonProperty("commands", Required = Required.Always)]
        public List<CommandDocument>? Commands { get; set; }
    }

    private sealed class CommandDocument
    {
        [JsonProperty("id", Required = Required.Always)]
        public string? Id { get; set; }

        [JsonProperty("title", Required = Required.Always)]
        public string? Title { get; set; }

        [JsonProperty("targetCategory", Required = Required.Always)]
        public string? TargetCategory { get; set; }

        [JsonProperty("commandText", Required = Required.Always)]
        public string? CommandText { get; set; }

        [JsonProperty("verificationStatus", Required = Required.Always)]
        public string? VerificationStatus { get; set; }

        [JsonProperty("isReadOnly", Required = Required.Always)]
        public bool IsReadOnly { get; set; }

        [JsonProperty("vendor", Required = Required.AllowNull)]
        public string? Vendor { get; set; }

        [JsonProperty("productFamily", Required = Required.AllowNull)]
        public string? ProductFamily { get; set; }

        [JsonProperty("minimumVersion", Required = Required.AllowNull)]
        public string? MinimumVersion { get; set; }

        [JsonProperty("maximumVersion", Required = Required.AllowNull)]
        public string? MaximumVersion { get; set; }

        [JsonProperty("checkItem", Required = Required.Always)]
        public string? CheckItem { get; set; }

        [JsonProperty("modelRange", Required = Required.Always)]
        public string? ModelRange { get; set; }

        [JsonProperty("accountRequirement", Required = Required.Always)]
        public string? AccountRequirement { get; set; }

        [JsonProperty("riskLevel", Required = Required.Always)]
        public string? RiskLevel { get; set; }

        [JsonProperty("timeoutSeconds", Required = Required.Always)]
        public int TimeoutSeconds { get; set; }

        [JsonProperty("pagingBehavior", Required = Required.Always)]
        public string? PagingBehavior { get; set; }

        [JsonProperty("resultDescription", Required = Required.Always)]
        public string? ResultDescription { get; set; }

        [JsonProperty("verificationDate", Required = Required.Always)]
        public string? VerificationDate { get; set; }

        [JsonProperty("officialSource", Required = Required.Always)]
        public string? OfficialSource { get; set; }
    }
}
