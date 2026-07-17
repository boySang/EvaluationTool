using System;
using System.IO;
using System.Linq;

namespace AssessmentTool.App.Services;

internal static class LocalExportDestinationPolicy
{
    internal static string ValidateNewFile(string path, string requiredExtension, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(path)
            || path.Any(character => character == '\0' || character == '\r' || character == '\n'))
        {
            throw new ArgumentException("请选择有效的本地导出路径。", parameterName);
        }

        if (!Path.IsPathRooted(path))
        {
            throw new ArgumentException("导出路径必须是完整绝对路径。", parameterName);
        }

        var fullPath = Path.GetFullPath(path);
        if (fullPath.StartsWith(@"\\?\", StringComparison.Ordinal)
            || fullPath.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            throw new ArgumentException("导出路径不能使用 Windows 设备路径。", parameterName);
        }

        if (!string.Equals(Path.GetExtension(fullPath), requiredExtension, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("导出文件扩展名必须是 " + requiredExtension + "。", parameterName);
        }

        var directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException("导出目录不存在。");
        }

        EnsureNoReparsePoints(directory);
        if (File.Exists(fullPath))
        {
            throw new IOException("目标文件已存在。为避免覆盖审计资料，请使用新的文件名。");
        }

        return fullPath;
    }

    internal static void EnsureNoReparsePoints(string directory)
    {
        var current = new DirectoryInfo(directory);
        while (current != null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("导出目录或其上级目录包含 Windows 重解析点。");
            }

            current = current.Parent;
        }
    }

    internal static void RevalidateNewFile(string fullPath)
    {
        var directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException("导出目录在写入过程中变得不可用。");
        }

        EnsureNoReparsePoints(directory);
        if (File.Exists(fullPath))
        {
            throw new IOException("目标文件在导出过程中已被其他程序创建，已阻止覆盖。");
        }
    }
}
