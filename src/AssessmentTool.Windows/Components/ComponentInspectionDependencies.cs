using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AssessmentTool.Windows.Components;

internal readonly struct ComponentHandleSnapshot : IEquatable<ComponentHandleSnapshot>
{
    internal ComponentHandleSnapshot(
        string canonicalAbsolutePath,
        long length,
        DateTime lastWriteTimeUtc,
        uint volumeSerialNumber,
        ulong fileIndex,
        uint linkCount,
        bool isReparsePoint)
    {
        CanonicalAbsolutePath = canonicalAbsolutePath ?? throw new ArgumentNullException(nameof(canonicalAbsolutePath));
        Length = length;
        LastWriteTimeUtc = lastWriteTimeUtc.ToUniversalTime();
        VolumeSerialNumber = volumeSerialNumber;
        FileIndex = fileIndex;
        LinkCount = linkCount;
        IsReparsePoint = isReparsePoint;
    }

    public string CanonicalAbsolutePath { get; }
    public long Length { get; }
    public DateTime LastWriteTimeUtc { get; }
    public uint VolumeSerialNumber { get; }
    public ulong FileIndex { get; }
    public uint LinkCount { get; }
    public bool IsReparsePoint { get; }

    public bool Equals(ComponentHandleSnapshot other)
    {
        return string.Equals(CanonicalAbsolutePath, other.CanonicalAbsolutePath, StringComparison.OrdinalIgnoreCase)
            && Length == other.Length
            && LastWriteTimeUtc.Equals(other.LastWriteTimeUtc)
            && VolumeSerialNumber == other.VolumeSerialNumber
            && FileIndex == other.FileIndex
            && LinkCount == other.LinkCount
            && IsReparsePoint == other.IsReparsePoint;
    }

    public override bool Equals(object? obj)
    {
        return obj is ComponentHandleSnapshot other && Equals(other);
    }

    public override int GetHashCode()
    {
        return StringComparer.OrdinalIgnoreCase.GetHashCode(CanonicalAbsolutePath)
            ^ Length.GetHashCode()
            ^ VolumeSerialNumber.GetHashCode()
            ^ FileIndex.GetHashCode();
    }
}

internal interface IComponentFileHandle : IDisposable
{
    Stream Stream { get; }

    ComponentHandleSnapshot CaptureSnapshot();

    void ValidateLease();
}

internal interface IComponentFileSystem
{
    string ValidateTrustedRoot(string root);

    string ResolveTrustedPath(string trustedRoot, string relativePath);

    bool FileExists(string absolutePath);

    IComponentFileHandle OpenRead(string trustedRoot, string absolutePath);
}

internal interface IComponentVersionReader
{
    string GetFileVersion(IComponentFileHandle handle, string absolutePath);
}

internal interface IComponentArchitectureReader
{
    ComponentArchitecture ReadArchitecture(Stream stream);
}

internal interface IComponentHashReader
{
    string ComputeSha256(Stream stream);
}

internal sealed class PhysicalComponentFileSystem : IComponentFileSystem
{
    private const uint GenericRead = 0x80000000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint ReparsePointAttribute = 0x00000400;
    private const int BufferSize = 4096;

    public string ValidateTrustedRoot(string root)
    {
        var fullPath = ValidateLocalFullPath(root, nameof(root));
        if (!Directory.Exists(fullPath))
        {
            throw new ArgumentException("组件受信根目录必须已存在。", nameof(root));
        }

        var snapshot = OpenDirectorySnapshot(fullPath);
        if (snapshot.IsReparsePoint
            || !string.Equals(snapshot.CanonicalAbsolutePath, fullPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("组件受信根目录不能是重解析路径。", nameof(root));
        }

        return snapshot.CanonicalAbsolutePath;
    }

    public string ResolveTrustedPath(string trustedRoot, string relativePath)
    {
        var candidate = Path.GetFullPath(Path.Combine(trustedRoot, relativePath));
        EnsureWithinRoot(trustedRoot, candidate);
        return candidate;
    }

    public bool FileExists(string absolutePath)
    {
        return File.Exists(absolutePath);
    }

    public IComponentFileHandle OpenRead(string trustedRoot, string absolutePath)
    {
        EnsureWithinRoot(trustedRoot, absolutePath);
        List<DirectoryLease>? directoryLeases = null;
        SafeFileHandle? handle = null;

        try
        {
            directoryLeases = OpenDirectoryLeaseChain(
                trustedRoot,
                Path.GetDirectoryName(absolutePath) ?? trustedRoot);
            handle = CreateFile(
                absolutePath,
                GenericRead,
                FileShare.Read,
                IntPtr.Zero,
                OpenExisting,
                FileFlagOpenReparsePoint | FileFlagSequentialScan,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                throw new IOException("组件文件无法以只读独占写入的方式打开。");
            }

            var snapshot = CaptureSnapshot(handle);
            if (snapshot.IsReparsePoint
                || snapshot.LinkCount != 1
                || !string.Equals(snapshot.CanonicalAbsolutePath, absolutePath, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("组件文件身份不安全。");
            }

            EnsureWithinRoot(trustedRoot, snapshot.CanonicalAbsolutePath);
            var leasedHandle = new Win32ComponentFileHandle(handle, snapshot, directoryLeases);
            handle = null;
            directoryLeases = null;
            return leasedHandle;
        }
        finally
        {
            handle?.Dispose();
            DisposeDirectoryLeases(directoryLeases);
        }
    }

    private static string ValidateLocalFullPath(string path, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(path)
            || path.StartsWith(@"\\", StringComparison.Ordinal)
            || path.StartsWith(@"\\?\", StringComparison.Ordinal)
            || !Path.IsPathRooted(path))
        {
            throw new ArgumentException("组件受信根必须是本机完整路径。", parameterName);
        }

        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root) || root.Length < 3 || root[1] != ':')
        {
            throw new ArgumentException("组件受信根必须是本机完整路径。", parameterName);
        }

        return string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase)
            ? root
            : fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static void EnsureWithinRoot(string trustedRoot, string path)
    {
        var fullPath = Path.GetFullPath(path);
        var prefix = trustedRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!string.Equals(fullPath, trustedRoot, StringComparison.OrdinalIgnoreCase)
            && !fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("组件路径超出受信根目录。");
        }
    }

    private static List<DirectoryLease> OpenDirectoryLeaseChain(string trustedRoot, string targetDirectory)
    {
        EnsureWithinRoot(trustedRoot, targetDirectory);
        var leases = new List<DirectoryLease>();
        var current = trustedRoot;
        try
        {
            leases.Add(OpenDirectoryLease(current));
            if (string.Equals(current, targetDirectory, StringComparison.OrdinalIgnoreCase))
            {
                return leases;
            }

            var relative = targetDirectory.Substring(trustedRoot.Length)
                .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            foreach (var segment in relative.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, segment);
                leases.Add(OpenDirectoryLease(current));
            }

            return leases;
        }
        catch
        {
            DisposeDirectoryLeases(leases);
            throw;
        }
    }

    private static DirectoryLease OpenDirectoryLease(string path)
    {
        var handle = CreateFile(
            path,
            FileReadAttributes,
            FileShare.ReadWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new IOException("组件目录链无法锁定。");
        }

        try
        {
            var snapshot = CaptureSnapshot(handle);
            if (snapshot.IsReparsePoint
                || !string.Equals(snapshot.CanonicalAbsolutePath, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("组件父目录包含重解析路径。");
            }

            return new DirectoryLease(handle, snapshot);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void DisposeDirectoryLeases(List<DirectoryLease>? leases)
    {
        if (leases == null)
        {
            return;
        }

        for (var index = leases.Count - 1; index >= 0; index--)
        {
            leases[index].Dispose();
        }
    }

    private static ComponentHandleSnapshot OpenDirectorySnapshot(string path)
    {
        using (var handle = CreateFile(
            path,
            FileReadAttributes,
            FileShare.ReadWrite | FileShare.Delete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                throw new IOException("组件目录身份无法验证。");
            }

            return CaptureSnapshot(handle);
        }
    }

    private static ComponentHandleSnapshot CaptureSnapshot(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new IOException("组件文件句柄身份无法读取。");
        }

        var length = ((long)information.FileSizeHigh << 32) | information.FileSizeLow;
        var fileIndex = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
        var lastWriteFileTime = ((long)information.LastWriteTime.dwHighDateTime << 32)
            | (uint)information.LastWriteTime.dwLowDateTime;
        return new ComponentHandleSnapshot(
            GetCanonicalFinalPath(handle),
            length,
            DateTime.FromFileTimeUtc(lastWriteFileTime),
            information.VolumeSerialNumber,
            fileIndex,
            information.NumberOfLinks,
            (information.FileAttributes & ReparsePointAttribute) != 0);
    }

    private static string GetCanonicalFinalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (capacity <= 32768)
        {
            var builder = new StringBuilder(capacity);
            var result = GetFinalPathNameByHandle(handle, builder, (uint)builder.Capacity, 0);
            if (result == 0)
            {
                throw new IOException("组件文件最终路径无法读取。");
            }

            if (result < builder.Capacity)
            {
                var path = builder.ToString();
                if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("组件文件不能位于网络路径。");
                }

                if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
                {
                    path = path.Substring(4);
                }

                var fullPath = Path.GetFullPath(path);
                var root = Path.GetPathRoot(fullPath);
                return string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase)
                    ? root!
                    : fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }

            capacity = checked((int)result + 1);
        }

        throw new PathTooLongException("组件文件最终路径过长。");
    }

    private sealed class Win32ComponentFileHandle : IComponentFileHandle
    {
        private readonly SafeFileHandle handle;
        private readonly ComponentHandleSnapshot initialSnapshot;
        private readonly List<DirectoryLease> directoryLeases;
        private bool disposed;

        public Win32ComponentFileHandle(
            SafeFileHandle handle,
            ComponentHandleSnapshot initialSnapshot,
            List<DirectoryLease> directoryLeases)
        {
            this.handle = handle;
            this.initialSnapshot = initialSnapshot;
            this.directoryLeases = directoryLeases;
            Stream = new FileStream(handle, FileAccess.Read, BufferSize, isAsync: false);
        }

        public Stream Stream { get; }

        public ComponentHandleSnapshot CaptureSnapshot()
        {
            ThrowIfDisposed();
            return PhysicalComponentFileSystem.CaptureSnapshot(handle);
        }

        public void ValidateLease()
        {
            ThrowIfDisposed();
            if (!initialSnapshot.Equals(PhysicalComponentFileSystem.CaptureSnapshot(handle)))
            {
                throw new InvalidDataException("组件文件租约身份发生变化。");
            }

            foreach (var directoryLease in directoryLeases)
            {
                directoryLease.ValidateIdentity();
            }
        }

        public void Dispose()
        {
            if (!disposed)
            {
                disposed = true;
                Stream.Dispose();
                handle.Dispose();
                DisposeDirectoryLeases(directoryLeases);
            }
        }

        private void ThrowIfDisposed()
        {
            if (disposed)
            {
                throw new ObjectDisposedException(nameof(Win32ComponentFileHandle));
            }
        }
    }

    private sealed class DirectoryLease : IDisposable
    {
        private readonly SafeFileHandle handle;
        private readonly ComponentHandleSnapshot identity;

        public DirectoryLease(SafeFileHandle handle, ComponentHandleSnapshot identity)
        {
            this.handle = handle;
            this.identity = identity;
        }

        public void ValidateIdentity()
        {
            var current = CaptureSnapshot(handle);
            if (current.IsReparsePoint
                || !string.Equals(current.CanonicalAbsolutePath, identity.CanonicalAbsolutePath, StringComparison.OrdinalIgnoreCase)
                || current.VolumeSerialNumber != identity.VolumeSerialNumber
                || current.FileIndex != identity.FileIndex)
            {
                throw new InvalidDataException("组件目录链租约身份发生变化。");
            }
        }

        public void Dispose()
        {
            handle.Dispose();
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        FileShare shareMode,
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
        uint filePathLength,
        uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}

internal sealed class PhysicalComponentVersionReader : IComponentVersionReader
{
    public string GetFileVersion(IComponentFileHandle handle, string absolutePath)
    {
        if (handle == null)
        {
            throw new ArgumentNullException(nameof(handle));
        }

        handle.ValidateLease();
        var before = handle.CaptureSnapshot();
        if (!string.Equals(before.CanonicalAbsolutePath, Path.GetFullPath(absolutePath), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("组件版本路径与已打开句柄不匹配。");
        }

        var version = FileVersionInfo.GetVersionInfo(absolutePath).FileVersion ?? string.Empty;
        handle.ValidateLease();
        var after = handle.CaptureSnapshot();
        if (!before.Equals(after))
        {
            throw new InvalidDataException("组件版本读取期间文件身份发生变化。");
        }

        return version;
    }
}

internal sealed class PeComponentArchitectureReader : IComponentArchitectureReader
{
    private const ushort X86Machine = 0x014c;
    private const ushort X64Machine = 0x8664;
    private const ushort Arm64Machine = 0xaa64;
    private const ushort Pe32Magic = 0x010b;
    private const ushort Pe32PlusMagic = 0x020b;
    private const ushort MinimumPe32OptionalHeader = 224;
    private const ushort MinimumPe32PlusOptionalHeader = 240;

    public ComponentArchitecture ReadArchitecture(Stream stream)
    {
        if (stream == null || !stream.CanSeek || !stream.CanRead || stream.Length < 64)
        {
            throw new InvalidDataException("组件文件不是有效 PE 文件。");
        }

        stream.Position = 0;
        var dosHeader = ReadExactly(stream, 64);
        try
        {
            if (dosHeader[0] != 0x4d || dosHeader[1] != 0x5a)
            {
                throw new InvalidDataException("组件文件 DOS 签名无效。");
            }

            var peOffset = ReadInt32(dosHeader, 0x3c);
            if (peOffset < 64 || peOffset > stream.Length - 26)
            {
                throw new InvalidDataException("组件文件 PE 头偏移无效。");
            }

            stream.Position = peOffset;
            var headers = ReadExactly(stream, 24);
            try
            {
                if (headers[0] != 0x50 || headers[1] != 0x45 || headers[2] != 0 || headers[3] != 0)
                {
                    throw new InvalidDataException("组件文件 PE 签名无效。");
                }

                var machine = ReadUInt16(headers, 4);
                var sections = ReadUInt16(headers, 6);
                var optionalHeaderSize = ReadUInt16(headers, 20);
                if (sections == 0 || stream.Length < peOffset + 24L + optionalHeaderSize)
                {
                    throw new InvalidDataException("组件文件 COFF 头无效。");
                }

                var optionalMagicBytes = ReadExactly(stream, 2);
                try
                {
                    var optionalMagic = ReadUInt16(optionalMagicBytes, 0);
                    if (machine == Arm64Machine)
                    {
                        throw new InvalidDataException("ARM64 组件架构暂不受支持。");
                    }

                    if (machine == X86Machine
                        && optionalMagic == Pe32Magic
                        && optionalHeaderSize >= MinimumPe32OptionalHeader)
                    {
                        return ComponentArchitecture.X86;
                    }

                    if (machine == X64Machine
                        && optionalMagic == Pe32PlusMagic
                        && optionalHeaderSize >= MinimumPe32PlusOptionalHeader)
                    {
                        return ComponentArchitecture.X64;
                    }

                    throw new InvalidDataException("组件文件 Machine 与 Optional Header 不一致。");
                }
                finally
                {
                    Array.Clear(optionalMagicBytes, 0, optionalMagicBytes.Length);
                }
            }
            finally
            {
                Array.Clear(headers, 0, headers.Length);
            }
        }
        finally
        {
            Array.Clear(dosHeader, 0, dosHeader.Length);
        }
    }

    private static byte[] ReadExactly(Stream stream, int count)
    {
        var bytes = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = stream.Read(bytes, offset, count - offset);
            if (read == 0)
            {
                Array.Clear(bytes, 0, bytes.Length);
                throw new EndOfStreamException();
            }

            offset += read;
        }

        return bytes;
    }

    private static ushort ReadUInt16(byte[] buffer, int offset)
    {
        return (ushort)(buffer[offset] | (buffer[offset + 1] << 8));
    }

    private static int ReadInt32(byte[] buffer, int offset)
    {
        return buffer[offset]
            | (buffer[offset + 1] << 8)
            | (buffer[offset + 2] << 16)
            | (buffer[offset + 3] << 24);
    }
}

internal sealed class Sha256ComponentHashReader : IComponentHashReader
{
    public string ComputeSha256(Stream stream)
    {
        if (stream == null || !stream.CanSeek || !stream.CanRead)
        {
            throw new InvalidDataException("组件文件无法从同一已打开句柄读取。");
        }

        stream.Position = 0;
        using (var hashAlgorithm = SHA256.Create())
        {
            var hash = hashAlgorithm.ComputeHash(stream);
            try
            {
                return BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
            }
            finally
            {
                Array.Clear(hash, 0, hash.Length);
            }
        }
    }
}
