using System;
using System.IO;
using System.Linq;

namespace AssessmentTool.Core.Domain;

public static class WindowsEvidenceRootPolicy
{
    public static string Normalize(string evidenceRoot, string parameterName)
    {
        if (evidenceRoot == null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (string.IsNullOrWhiteSpace(evidenceRoot)
            || evidenceRoot.Length > 1024
            || evidenceRoot.Any(character => character == '\0' || character == '\r' || character == '\n')
            || !IsFullyQualifiedWindowsPath(evidenceRoot))
        {
            throw new ArgumentException(
                "Evidence root must be a fully-qualified Windows drive or UNC path.",
                parameterName);
        }

        var fullPath = Path.GetFullPath(evidenceRoot);
        if (!Path.IsPathRooted(fullPath))
        {
            throw new ArgumentException("Evidence root must be an absolute Windows path.", parameterName);
        }

        var pathRoot = Path.GetPathRoot(fullPath);
        return string.Equals(fullPath, pathRoot, StringComparison.OrdinalIgnoreCase)
            ? fullPath
            : fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    public static string ResolveContainedPath(
        string evidenceRoot,
        string relativePath,
        string parameterName)
    {
        var root = Normalize(evidenceRoot, nameof(evidenceRoot));
        var normalizedRelativePath = WindowsEvidenceRelativePathPolicy.Normalize(relativePath, parameterName);
        var platformRelativePath = normalizedRelativePath.Replace('\\', Path.DirectorySeparatorChar);
        var rootWithSeparator = EnsureTrailingSeparator(root);
        var combinedPath = Path.GetFullPath(Path.Combine(root, platformRelativePath));
        if (!combinedPath.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Evidence path resolves outside the project evidence root.", parameterName);
        }

        return combinedPath;
    }

    public static string EnsureTrailingSeparator(string normalizedEvidenceRoot)
    {
        if (string.IsNullOrWhiteSpace(normalizedEvidenceRoot))
        {
            throw new ArgumentException("Evidence root cannot be blank.", nameof(normalizedEvidenceRoot));
        }

        return normalizedEvidenceRoot.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
            || normalizedEvidenceRoot.EndsWith(Path.AltDirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? normalizedEvidenceRoot
                : normalizedEvidenceRoot + Path.DirectorySeparatorChar;
    }

    public static void EnsureNoExistingReparsePoints(string evidenceRoot)
    {
        var current = Normalize(evidenceRoot, nameof(evidenceRoot));
        while (!string.IsNullOrEmpty(current))
        {
            if ((Directory.Exists(current) || File.Exists(current))
                && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException(
                    "Evidence root or one of its existing ancestors is a Windows reparse point.");
            }

            var parent = Directory.GetParent(current);
            if (parent == null || string.Equals(parent.FullName, current, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            current = parent.FullName;
        }
    }

    private static bool IsFullyQualifiedWindowsPath(string path)
    {
        if (path.Length >= 3
            && char.IsLetter(path[0])
            && path[1] == ':'
            && (path[2] == '\\' || path[2] == '/'))
        {
            return true;
        }

        var isUnc = path.StartsWith("\\\\", StringComparison.Ordinal)
            || path.StartsWith("//", StringComparison.Ordinal);
        if (!isUnc
            || path.StartsWith("\\\\?\\", StringComparison.Ordinal)
            || path.StartsWith("\\\\.\\", StringComparison.Ordinal)
            || path.StartsWith("//?/", StringComparison.Ordinal)
            || path.StartsWith("//./", StringComparison.Ordinal))
        {
            return false;
        }

        var segments = path.Substring(2).Split(new[] { '/', '\\' }, StringSplitOptions.None);
        return segments.Length >= 2
            && IsValidUncSegment(segments[0])
            && IsValidUncSegment(segments[1]);
    }

    private static bool IsValidUncSegment(string segment)
    {
        return !string.IsNullOrWhiteSpace(segment)
            && segment != "."
            && segment != "..";
    }
}
