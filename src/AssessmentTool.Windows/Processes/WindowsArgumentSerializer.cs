using System;
using System.Collections.Generic;
using System.Text;

namespace AssessmentTool.Windows.Processes;

internal static class WindowsArgumentSerializer
{
    /// <summary>
    /// Serializes argv[1+] argument tokens only. The executable path and trusted argv[0] are supplied separately.
    /// </summary>
    internal static string Serialize(IReadOnlyList<string> argumentTokens)
    {
        if (argumentTokens == null)
        {
            throw new ArgumentNullException(nameof(argumentTokens));
        }

        var commandLine = new StringBuilder();
        for (var index = 0; index < argumentTokens.Count; index++)
        {
            var token = argumentTokens[index];
            ValidateToken(token, index, nameof(argumentTokens));

            if (index > 0)
            {
                commandLine.Append(' ');
            }

            AppendToken(commandLine, token);
        }

        return commandLine.ToString();
    }

    private static void ValidateToken(string? token, int index, string parameterName)
    {
        if (token == null)
        {
            throw new ArgumentException("命令行参数不能包含 null token。索引：" + index + "。", parameterName);
        }

        if (token.IndexOf('\0') >= 0 || token.IndexOf('\r') >= 0 || token.IndexOf('\n') >= 0)
        {
            throw new ArgumentException("命令行参数不能包含 NUL、CR 或 LF 控制字符。索引：" + index + "。", parameterName);
        }
    }

    private static void AppendToken(StringBuilder commandLine, string token)
    {
        if (!RequiresQuotes(token))
        {
            commandLine.Append(token);
            return;
        }

        commandLine.Append('"');
        var backslashCount = 0;

        foreach (var value in token)
        {
            if (value == '\\')
            {
                backslashCount++;
                continue;
            }

            if (value == '"')
            {
                commandLine.Append('\\', (backslashCount * 2) + 1);
                commandLine.Append('"');
                backslashCount = 0;
                continue;
            }

            commandLine.Append('\\', backslashCount);
            commandLine.Append(value);
            backslashCount = 0;
        }

        commandLine.Append('\\', backslashCount * 2);
        commandLine.Append('"');
    }

    private static bool RequiresQuotes(string token)
    {
        if (token.Length == 0)
        {
            return true;
        }

        foreach (var value in token)
        {
            if (char.IsWhiteSpace(value) || value == '"')
            {
                return true;
            }
        }

        return false;
    }
}
