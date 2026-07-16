using System;
using System.Collections.Generic;

namespace AssessmentTool.Core.Domain;

public static class WindowsEvidenceRelativePathPolicy
{
    private static readonly HashSet<string> ReservedDeviceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CLOCK$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"
    };

    private static readonly char[] InvalidFileNameCharacters = { '<', '>', ':', '"', '|', '?', '*' };

    public static string Normalize(string path, string parameterName)
    {
        if (path == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (string.IsNullOrWhiteSpace(path)
            || path.StartsWith("/", StringComparison.Ordinal)
            || path.StartsWith("\\", StringComparison.Ordinal)
            || path.IndexOf('%') >= 0
            || path.IndexOfAny(InvalidFileNameCharacters) >= 0
            || ContainsControlCharacter(path))
        {
            throw new ArgumentException("Evidence path must be an unambiguous Windows relative path.", parameterName);
        }

        var segments = path.Split(new[] { '/', '\\' }, StringSplitOptions.None);
        foreach (var segment in segments)
        {
            if (string.IsNullOrWhiteSpace(segment)
                || segment == "."
                || segment == ".."
                || segment.EndsWith(".", StringComparison.Ordinal)
                || segment.EndsWith(" ", StringComparison.Ordinal)
                || IsReservedDeviceName(segment))
            {
                throw new ArgumentException("Evidence path contains an invalid Windows path segment.", parameterName);
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
        var dotIndex = segment.IndexOf('.');
        var baseName = dotIndex < 0 ? segment : segment.Substring(0, dotIndex);
        return ReservedDeviceNames.Contains(baseName);
    }
}
