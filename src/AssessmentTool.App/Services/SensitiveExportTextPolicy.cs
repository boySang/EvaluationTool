using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace AssessmentTool.App.Services;

internal static class SensitiveExportTextPolicy
{
    private static readonly Regex AssignmentPattern = new Regex(
        @"(?ix)\b(?:password|passwd|pwd|secret|token|access[_-]?key|private[_-]?key)\b\s*(?:=|:)\s*[""']?[^\s,;}""']+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex AuthorizationPattern = new Regex(
        @"(?ix)\bauthorization\s*:\s*(?:bearer|basic)\s+\S+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex ConnectionStringPattern = new Regex(
        @"(?ix)\b(?:server|data\s+source|host)\s*=\s*[^;]+;[^\r\n]*(?:password|pwd)\s*=",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    internal static void EnsureNoLikelySecrets(IEnumerable<string?> values)
    {
        if (values == null)
        {
            throw new ArgumentNullException(nameof(values));
        }

        foreach (var value in values)
        {
            if (string.IsNullOrEmpty(value))
            {
                continue;
            }

            if ((value.IndexOf("-----BEGIN", StringComparison.OrdinalIgnoreCase) >= 0
                    && value.IndexOf("PRIVATE KEY-----", StringComparison.OrdinalIgnoreCase) >= 0)
                || AssignmentPattern.IsMatch(value)
                || AuthorizationPattern.IsMatch(value)
                || ConnectionStringPattern.IsMatch(value))
            {
                throw new InvalidDataException(
                    "导出内容中检测到疑似密码、令牌、私钥或连接字符串，已阻止导出。请先清理相关自由文本记录。");
            }
        }
    }
}
