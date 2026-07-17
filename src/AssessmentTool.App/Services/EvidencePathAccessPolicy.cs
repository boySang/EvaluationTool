using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using AssessmentTool.Core.Domain;
using Microsoft.Win32.SafeHandles;

namespace AssessmentTool.App.Services;

internal static class EvidencePathAccessPolicy
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileAttributeReparsePoint = 0x00000400;

    internal static string ResolveExistingFile(string evidenceRoot, string relativePath)
    {
        var root = WindowsEvidenceRootPolicy.Normalize(evidenceRoot, nameof(evidenceRoot));
        WindowsEvidenceRootPolicy.EnsureNoExistingReparsePoints(root);
        var path = WindowsEvidenceRootPolicy.ResolveContainedPath(
            root,
            relativePath,
            nameof(relativePath));
        EnsureNoReparsePoints(root, path);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("证据文件不存在。", path);
        }

        using (OpenVerifiedFile(root, relativePath))
        {
            return path;
        }
    }

    internal static FileStream OpenVerifiedFile(string evidenceRoot, string relativePath)
    {
        var root = WindowsEvidenceRootPolicy.Normalize(evidenceRoot, nameof(evidenceRoot));
        WindowsEvidenceRootPolicy.EnsureNoExistingReparsePoints(root);
        var expectedPath = WindowsEvidenceRootPolicy.ResolveContainedPath(
            root,
            relativePath,
            nameof(relativePath));
        EnsureNoReparsePoints(root, expectedPath);

        var handle = CreateFile(
            expectedPath,
            GenericRead,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error(), "证据文件无法安全打开。");
        }

        try
        {
            ByHandleFileInformation information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "无法读取证据文件句柄属性。");
            }

            if ((information.FileAttributes & FileAttributeReparsePoint) != 0)
            {
                throw new InvalidDataException("证据文件句柄指向 Windows 重解析点。");
            }

            var finalPath = GetFinalPath(handle);
            if (!string.Equals(
                Path.GetFullPath(expectedPath),
                Path.GetFullPath(finalPath),
                StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("证据文件最终路径与项目索引路径不一致。");
            }

            return new FileStream(handle, FileAccess.Read, 64 * 1024, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static void EnsureNoReparsePoints(string root, string path)
    {
        var relativePath = path.Substring(root.Length)
            .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = root;
        foreach (var segment in relativePath.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((Directory.Exists(current) || File.Exists(current))
                && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException("证据路径包含 Windows 重解析点，已阻止访问。");
            }
        }
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        var buffer = new StringBuilder(32768);
        var length = GetFinalPathNameByHandle(handle, buffer, buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法解析证据文件最终路径。");
        }

        var path = buffer.ToString();
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path.Substring(8);
        }

        return path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)
            ? path.Substring(4)
            : path;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        int filePathSize,
        uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        internal uint CreationTimeLow;
        internal uint CreationTimeHigh;
        internal uint LastAccessTimeLow;
        internal uint LastAccessTimeHigh;
        internal uint LastWriteTimeLow;
        internal uint LastWriteTimeHigh;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }
}
