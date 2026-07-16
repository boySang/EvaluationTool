using System;
using System.Collections.Generic;
using System.IO;

namespace AssessmentTool.Windows.Components;

public enum ComponentArchitecture
{
    X86,
    X64
}

public sealed class ComponentDefinition
{
    private static readonly HashSet<string> ReservedDeviceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CLOCK$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    private static readonly char[] InvalidPathCharacters = { '<', '>', ':', '"', '|', '?', '*' };

    internal ComponentDefinition(
        string id,
        string trustedRelativePath,
        string expectedSha256,
        string minimumVersion,
        ComponentArchitecture requiredArchitecture,
        string affectedFeature)
    {
        Id = RequiredText(id, nameof(id));
        TrustedRelativePath = ValidateTrustedRelativePath(trustedRelativePath);
        ExpectedSha256 = ValidateSha256(expectedSha256, nameof(expectedSha256));
        MinimumVersion = ValidateVersion(minimumVersion, nameof(minimumVersion));
        if (!Enum.IsDefined(typeof(ComponentArchitecture), requiredArchitecture))
        {
            throw new ArgumentOutOfRangeException(nameof(requiredArchitecture));
        }

        RequiredArchitecture = requiredArchitecture;
        AffectedFeature = RequiredText(affectedFeature, nameof(affectedFeature));
    }

    public string Id { get; }
    public string TrustedRelativePath { get; }
    public string ExpectedSha256 { get; }
    public string MinimumVersion { get; }
    public ComponentArchitecture RequiredArchitecture { get; }
    public string AffectedFeature { get; }

    internal string DefinitionKey => string.Join(
        "|",
        Id,
        TrustedRelativePath,
        ExpectedSha256.ToLowerInvariant(),
        MinimumVersion,
        RequiredArchitecture.ToString(),
        AffectedFeature);

    internal static ComponentDefinition Plink(
        string trustedRelativePath,
        string expectedSha256,
        string minimumVersion)
    {
        return new ComponentDefinition(
            "plink",
            trustedRelativePath,
            expectedSha256,
            minimumVersion,
            ComponentArchitecture.X64,
            "SSH连接");
    }

    internal static bool IsSha256(string? value)
    {
        if (value == null || value.Length != 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            var digit = character >= '0' && character <= '9';
            var lowercase = character >= 'a' && character <= 'f';
            var uppercase = character >= 'A' && character <= 'F';
            if (!digit && !lowercase && !uppercase)
            {
                return false;
            }
        }

        return true;
    }

    internal static bool TryParseStrictVersion(string? value, out Version version)
    {
        version = new Version();
        if (string.IsNullOrWhiteSpace(value)
            || !Version.TryParse(value, out var parsed)
            || parsed.Build < 0
            || parsed.Revision < 0
            || !string.Equals(parsed.ToString(), value, StringComparison.Ordinal))
        {
            return false;
        }

        version = parsed;
        return true;
    }

    private static string RequiredText(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("组件定义字段不能为空。", parameterName);
        }

        return value;
    }

    private static string ValidateTrustedRelativePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || Path.IsPathRooted(value)
            || value.IndexOfAny(InvalidPathCharacters) >= 0)
        {
            throw new ArgumentException("组件路径必须是安全的受信任相对路径。", nameof(value));
        }

        var segments = value.Split(new[] { '/', '\\' }, StringSplitOptions.None);
        foreach (var segment in segments)
        {
            if (string.IsNullOrWhiteSpace(segment)
                || segment == "."
                || segment == ".."
                || segment.EndsWith(".", StringComparison.Ordinal)
                || segment.EndsWith(" ", StringComparison.Ordinal)
                || ContainsControlCharacter(segment)
                || IsReservedDeviceName(segment))
            {
                throw new ArgumentException("组件路径包含不安全的 Windows 路径段。", nameof(value));
            }
        }

        return string.Join("\\", segments);
    }

    private static bool ContainsControlCharacter(string value)
    {
        foreach (var character in value)
        {
            if (character <= '\u001f')
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsReservedDeviceName(string segment)
    {
        var dot = segment.IndexOf('.');
        var baseName = dot < 0 ? segment : segment.Substring(0, dot);
        return ReservedDeviceNames.Contains(baseName);
    }

    private static string ValidateSha256(string value, string parameterName)
    {
        if (!IsSha256(value))
        {
            throw new ArgumentException("组件 SHA-256 必须是 64 位十六进制值。", parameterName);
        }

        return value;
    }

    private static string ValidateVersion(string value, string parameterName)
    {
        if (!TryParseStrictVersion(value, out _))
        {
            throw new ArgumentException("组件版本必须是严格的四段数字版本。", parameterName);
        }

        return value;
    }
}
