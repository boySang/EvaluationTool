using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AssessmentTool.Windows.Credentials;

internal readonly struct CredentialFileIdentity
{
    internal CredentialFileIdentity(
        string canonicalAbsolutePath,
        uint volumeSerialNumber,
        ulong fileIndex,
        uint linkCount)
    {
        CanonicalAbsolutePath = canonicalAbsolutePath;
        VolumeSerialNumber = volumeSerialNumber;
        FileIndex = fileIndex;
        LinkCount = linkCount;
    }

    public string CanonicalAbsolutePath { get; }
    public uint VolumeSerialNumber { get; }
    public ulong FileIndex { get; }
    public uint LinkCount { get; }

    internal bool Matches(CredentialFileIdentity other)
    {
        return VolumeSerialNumber == other.VolumeSerialNumber
            && FileIndex == other.FileIndex
            && string.Equals(CanonicalAbsolutePath, other.CanonicalAbsolutePath, StringComparison.OrdinalIgnoreCase);
    }
}

internal sealed class CredentialVerifiedFile : IDisposable
{
    private readonly SafeFileHandle handle;

    internal CredentialVerifiedFile(SafeFileHandle handle, CredentialFileIdentity identity)
    {
        this.handle = handle;
        Identity = identity;
        Stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
    }

    public Stream Stream { get; }
    public CredentialFileIdentity Identity { get; }

    public void Dispose()
    {
        Stream.Dispose();
        handle.Dispose();
    }
}

internal sealed class CredentialFileSecurity
{
    private const uint GenericRead = 0x80000000;
    private const uint ReadControl = 0x00020000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint ReparsePointAttribute = 0x00000400;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const int SeFileObject = 1;
    private const int FileDispositionInfo = 4;
    private const int SharingViolation = 32;
    private const int LockViolation = 33;
    private const int FileNotFound = 2;
    private const int PathNotFound = 3;
    private const int AccessDenied = 5;
    private const int BufferSize = 4096;

    private readonly SecurityIdentifier currentUser;

    public CredentialFileSecurity(string trustedRoot)
    {
        TrustedRoot = ValidateTrustedLocalRoot(trustedRoot);
        currentUser = WindowsIdentity.GetCurrent().User
            ?? throw Failure(CredentialVaultFailure.AccessControlViolation, "无法确定当前 Windows 用户，已拒绝访问凭据存储。");
        ValidateDirectoryPath(TrustedRoot, requireSecureAclOnTarget: false);
    }

    public string TrustedRoot { get; }

    public string ResolveUnderTrustedRoot(string relativeName)
    {
        if (string.IsNullOrWhiteSpace(relativeName))
        {
            throw new ArgumentException("凭据存储相对路径不能为空。", nameof(relativeName));
        }

        var candidate = Path.GetFullPath(Path.Combine(TrustedRoot, relativeName));
        EnsureWithinTrustedRoot(candidate);
        return candidate;
    }

    public void CreateOrValidateSecureDirectory(string path)
    {
        EnsureWithinTrustedRoot(path);
        ValidateDirectoryPath(Path.GetDirectoryName(path) ?? TrustedRoot, requireSecureAclOnTarget: false);
        if (!Directory.Exists(path))
        {
            Directory.CreateDirectory(path, CreateDirectorySecurity());
        }

        ValidateDirectoryPath(path, requireSecureAclOnTarget: true);
    }

    public void ValidateExistingSecureDirectory(string path)
    {
        EnsureWithinTrustedRoot(path);
        if (!Directory.Exists(path))
        {
            throw Failure(CredentialVaultFailure.NotFound, "凭据存储尚未初始化。");
        }

        ValidateDirectoryPath(path, requireSecureAclOnTarget: true);
    }

    public CredentialFileIdentity GetSecureDirectoryIdentity(string path)
    {
        EnsureWithinTrustedRoot(path);
        ValidateDirectoryPath(Path.GetDirectoryName(path) ?? TrustedRoot, requireSecureAclOnTarget: false);
        return OpenAndValidateDirectoryIdentity(path, DeleteAccess | ReadControl | FileReadAttributes);
    }

    public FileStream CreateSecureFile(string path)
    {
        EnsureWithinTrustedRoot(path);
        ValidateDirectoryPath(Path.GetDirectoryName(path) ?? TrustedRoot, requireSecureAclOnTarget: true);
        FileStream? stream = null;
        try
        {
            stream = new FileStream(
                path,
                FileMode.CreateNew,
                FileSystemRights.FullControl,
                FileShare.None,
                BufferSize,
                FileOptions.WriteThrough,
                CreateFileSecurity());
            ValidateFileHandle(stream.SafeFileHandle, path, requireSingleLink: true, requireSecureAcl: true);
            return stream;
        }
        catch (CredentialVaultException)
        {
            stream?.Dispose();
            TryDeleteVerifiedPath(path);
            throw;
        }
        catch (Exception)
        {
            stream?.Dispose();
            TryDeleteVerifiedPath(path);
            throw Failure(CredentialVaultFailure.StorageFailure, "无法安全创建凭据文件。");
        }
    }

    public CredentialFileIdentity GetSecureFileIdentity(FileStream stream, string path)
    {
        if (stream == null)
        {
            throw new ArgumentNullException(nameof(stream));
        }

        EnsureWithinTrustedRoot(path);
        return ValidateFileHandle(stream.SafeFileHandle, path, requireSingleLink: true, requireSecureAcl: true);
    }

    public CredentialVerifiedFile OpenVerifiedRead(string path)
    {
        EnsureWithinTrustedRoot(path);
        ValidateDirectoryPath(Path.GetDirectoryName(path) ?? TrustedRoot, requireSecureAclOnTarget: true);
        var handle = CreateFile(
            path,
            GenericRead | ReadControl,
            FileShare.Read,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw Failure(CredentialVaultFailure.StorageFailure, "凭据文件无法安全打开。");
        }

        try
        {
            var identity = ValidateFileHandle(handle, path, requireSingleLink: true, requireSecureAcl: true);
            return new CredentialVerifiedFile(handle, identity);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public void ValidateSecureFile(string path, bool requireSingleLink)
    {
        using (var verified = OpenVerifiedRead(path))
        {
            if (requireSingleLink && verified.Identity.LinkCount != 1)
            {
                throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据文件链接身份不安全。");
            }
        }
    }

    public void ValidateNewlyWrittenFile(string path)
    {
        try
        {
            ValidateSecureFile(path, requireSingleLink: true);
        }
        catch
        {
            TryDeleteVerifiedPath(path);
            throw;
        }
    }

    public void DeleteFile(string path)
    {
        if (!TryDeleteFile(path, expectedIdentity: null, ignoreSharingViolation: false))
        {
            throw Failure(CredentialVaultFailure.StorageFailure, "凭据文件当前正在使用，无法安全删除。");
        }
    }

    public void DeleteFile(string path, CredentialFileIdentity expectedIdentity)
    {
        if (!TryDeleteFile(path, expectedIdentity, ignoreSharingViolation: false))
        {
            throw Failure(CredentialVaultFailure.StorageFailure, "凭据文件当前正在使用，无法安全删除。");
        }
    }

    public bool TryDeleteFile(string path)
    {
        return TryDeleteFile(path, expectedIdentity: null, ignoreSharingViolation: true);
    }

    public void DeleteDirectory(string path, CredentialFileIdentity expectedIdentity)
    {
        EnsureWithinTrustedRoot(path);
        if (PathsEqual(path, TrustedRoot))
        {
            throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "拒绝删除凭据受信任根目录。");
        }

        ValidateDirectoryPath(Path.GetDirectoryName(path) ?? TrustedRoot, requireSecureAclOnTarget: false);
        using (var handle = CreateFile(
            path,
            DeleteAccess | ReadControl | FileReadAttributes,
            FileShare.ReadWrite | FileShare.Delete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == FileNotFound || error == PathNotFound)
                {
                    return;
                }

                throw Failure(CredentialVaultFailure.StorageFailure, "凭据临时目录无法通过验证句柄删除。");
            }

            var actualIdentity = ValidateDirectoryHandleIdentity(handle, path, requireSecureAcl: true);
            EnsureExpectedIdentity(actualIdentity, expectedIdentity);
            DeleteByHandle(handle);
        }
    }

    public bool TryDeleteStaleFile(string path, DateTime notNewerThanUtc)
    {
        EnsureWithinTrustedRoot(path);
        ValidateDirectoryPath(Path.GetDirectoryName(path) ?? TrustedRoot, requireSecureAclOnTarget: true);
        using (var handle = CreateFile(
            path,
            DeleteAccess | ReadControl | FileReadAttributes,
            FileShare.Read,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == FileNotFound || error == PathNotFound
                    || error == SharingViolation || error == LockViolation)
                {
                    return false;
                }

                if (error == AccessDenied)
                {
                    throw Failure(CredentialVaultFailure.AccessControlViolation, "凭据临时文件访问控制拒绝安全清理。");
                }

                throw Failure(CredentialVaultFailure.StorageFailure, "凭据临时文件无法通过验证句柄清理。");
            }

            ValidateFileHandle(handle, path, requireSingleLink: true, requireSecureAcl: true);
            var information = ReadHandleInformation(handle);
            if (ReadLastWriteTimeUtc(information) > notNewerThanUtc.ToUniversalTime())
            {
                return false;
            }

            DeleteByHandle(handle);
            return true;
        }
    }

    public bool TryDeleteStaleDirectory(
        string path,
        CredentialFileIdentity expectedIdentity,
        DateTime notNewerThanUtc)
    {
        EnsureWithinTrustedRoot(path);
        if (PathsEqual(path, TrustedRoot))
        {
            throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "拒绝删除凭据受信任根目录。");
        }

        ValidateDirectoryPath(Path.GetDirectoryName(path) ?? TrustedRoot, requireSecureAclOnTarget: false);
        using (var handle = CreateFile(
            path,
            DeleteAccess | ReadControl | FileReadAttributes,
            FileShare.ReadWrite | FileShare.Delete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == FileNotFound || error == PathNotFound)
                {
                    return true;
                }

                if (error == SharingViolation || error == LockViolation)
                {
                    return false;
                }

                throw Failure(CredentialVaultFailure.StorageFailure, "凭据临时目录无法通过验证句柄清理。");
            }

            var actualIdentity = ValidateDirectoryHandleIdentity(handle, path, requireSecureAcl: true);
            EnsureExpectedIdentity(actualIdentity, expectedIdentity);
            if (ReadLastWriteTimeUtc(ReadHandleInformation(handle)) > notNewerThanUtc.ToUniversalTime())
            {
                return false;
            }

            DeleteByHandle(handle);
            return true;
        }
    }

    private bool TryDeleteFile(
        string path,
        CredentialFileIdentity? expectedIdentity,
        bool ignoreSharingViolation)
    {
        EnsureWithinTrustedRoot(path);
        ValidateDirectoryPath(Path.GetDirectoryName(path) ?? TrustedRoot, requireSecureAclOnTarget: true);
        using (var handle = CreateFile(
            path,
            DeleteAccess | ReadControl | FileReadAttributes,
            FileShare.Read,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == FileNotFound || error == PathNotFound)
                {
                    return true;
                }

                if (error == AccessDenied)
                {
                    throw Failure(CredentialVaultFailure.AccessControlViolation, "凭据文件访问控制拒绝安全删除。");
                }

                if (ignoreSharingViolation && (error == SharingViolation || error == LockViolation))
                {
                    return false;
                }

                throw Failure(CredentialVaultFailure.StorageFailure, "凭据文件无法通过验证句柄删除。");
            }

            var actualIdentity = ValidateFileHandle(handle, path, requireSingleLink: true, requireSecureAcl: true);
            if (expectedIdentity.HasValue)
            {
                EnsureExpectedIdentity(actualIdentity, expectedIdentity.Value);
            }

            DeleteByHandle(handle);
            return true;
        }
    }

    private static void DeleteByHandle(SafeFileHandle handle)
    {
        var disposition = new FileDispositionInformation { DeleteFile = true };
        if (!SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            ref disposition,
            Marshal.SizeOf(typeof(FileDispositionInformation))))
        {
            throw Failure(CredentialVaultFailure.StorageFailure, "凭据文件无法通过验证句柄删除。");
        }
    }

    private static DateTime ReadLastWriteTimeUtc(ByHandleFileInformation information)
    {
        var fileTime = ((long)information.LastWriteTime.dwHighDateTime << 32)
            | (uint)information.LastWriteTime.dwLowDateTime;
        return DateTime.FromFileTimeUtc(fileTime);
    }

    private static string ValidateTrustedLocalRoot(string root)
    {
        if (string.IsNullOrWhiteSpace(root)
            || root.StartsWith(@"\\", StringComparison.Ordinal)
            || root.StartsWith(@"\\?\", StringComparison.Ordinal)
            || !Path.IsPathRooted(root))
        {
            throw new ArgumentException("凭据根目录必须是调用方信任的本机完整路径。", nameof(root));
        }

        var fullPath = Path.GetFullPath(root);
        var pathRoot = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(pathRoot)
            || pathRoot.Length < 3
            || pathRoot[1] != ':'
            || (pathRoot[2] != '\\' && pathRoot[2] != '/'))
        {
            throw new ArgumentException("凭据根目录必须是调用方信任的本机完整路径。", nameof(root));
        }

        if (!Directory.Exists(fullPath))
        {
            throw new ArgumentException("调用方信任的凭据根目录必须已存在。", nameof(root));
        }

        return string.Equals(fullPath, pathRoot, StringComparison.OrdinalIgnoreCase)
            ? pathRoot
            : fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private void EnsureWithinTrustedRoot(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var prefix = EnsureTrailingSeparator(TrustedRoot);
        if (!string.Equals(fullPath, TrustedRoot, StringComparison.OrdinalIgnoreCase)
            && !fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据路径超出受信任根目录。");
        }
    }

    private void ValidateDirectoryPath(string targetDirectory, bool requireSecureAclOnTarget)
    {
        var fullTarget = Path.GetFullPath(targetDirectory);
        var volumeRoot = Path.GetPathRoot(fullTarget)
            ?? throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据目录缺少本机卷根。");
        var current = volumeRoot;
        ValidateDirectoryHandle(current, requireSecureAcl: requireSecureAclOnTarget && PathsEqual(current, fullTarget));
        if (PathsEqual(current, fullTarget))
        {
            return;
        }

        var relative = fullTarget.Substring(volumeRoot.Length);
        foreach (var segment in relative.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            ValidateDirectoryHandle(current, requireSecureAcl: requireSecureAclOnTarget && PathsEqual(current, fullTarget));
        }
    }

    private void ValidateDirectoryHandle(string path, bool requireSecureAcl)
    {
        using (var handle = CreateFile(
            path,
            FileReadAttributes | (requireSecureAcl ? ReadControl : 0),
            FileShare.ReadWrite | FileShare.Delete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据目录身份无法验证。");
            }

            _ = ValidateDirectoryHandleIdentity(handle, path, requireSecureAcl);
        }
    }

    private CredentialFileIdentity OpenAndValidateDirectoryIdentity(string path, uint desiredAccess)
    {
        using (var handle = CreateFile(
            path,
            desiredAccess,
            FileShare.ReadWrite | FileShare.Delete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据目录身份无法验证。");
            }

            return ValidateDirectoryHandleIdentity(handle, path, requireSecureAcl: true);
        }
    }

    private CredentialFileIdentity ValidateDirectoryHandleIdentity(
        SafeFileHandle handle,
        string expectedPath,
        bool requireSecureAcl)
    {
        var information = ReadHandleInformation(handle);
        var finalPath = GetCanonicalFinalPath(handle);
        if ((information.FileAttributes & ReparsePointAttribute) != 0
            || !PathsEqual(finalPath, Path.GetFullPath(expectedPath)))
        {
            throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据目录祖先链包含重解析或替换路径。");
        }

        if (requireSecureAcl)
        {
            ValidateHandleAcl(handle);
        }

        return new CredentialFileIdentity(
            finalPath,
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow,
            information.NumberOfLinks);
    }

    private CredentialFileIdentity ValidateFileHandle(
        SafeFileHandle handle,
        string expectedPath,
        bool requireSingleLink,
        bool requireSecureAcl)
    {
        var information = ReadHandleInformation(handle);
        var finalPath = GetCanonicalFinalPath(handle);
        if ((information.FileAttributes & ReparsePointAttribute) != 0
            || !PathsEqual(finalPath, Path.GetFullPath(expectedPath))
            || (requireSingleLink && information.NumberOfLinks != 1))
        {
            throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据文件句柄身份不安全。");
        }

        if (requireSecureAcl)
        {
            ValidateHandleAcl(handle);
        }

        return new CredentialFileIdentity(
            finalPath,
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow,
            information.NumberOfLinks);
    }

    private void ValidateHandleAcl(SafeFileHandle handle)
    {
        IntPtr owner;
        IntPtr group;
        IntPtr dacl;
        IntPtr sacl;
        IntPtr securityDescriptor;
        var result = GetSecurityInfo(
            handle.DangerousGetHandle(),
            SeFileObject,
            OwnerSecurityInformation | DaclSecurityInformation,
            out owner,
            out group,
            out dacl,
            out sacl,
            out securityDescriptor);
        if (result != 0 || securityDescriptor == IntPtr.Zero)
        {
            throw Failure(CredentialVaultFailure.AccessControlViolation, "凭据存储句柄访问控制无法读取。");
        }

        try
        {
            var length = checked((int)GetSecurityDescriptorLength(securityDescriptor));
            var bytes = new byte[length];
            Marshal.Copy(securityDescriptor, bytes, 0, bytes.Length);
            var descriptor = new RawSecurityDescriptor(bytes, 0);
            if (!Equals(descriptor.Owner, currentUser)
                || (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0
                || descriptor.DiscretionaryAcl == null
                || descriptor.DiscretionaryAcl.Count != 1)
            {
                throw Failure(CredentialVaultFailure.AccessControlViolation, "凭据存储句柄访问控制不安全。");
            }

            var ace = descriptor.DiscretionaryAcl[0] as CommonAce;
            if (ace == null
                || (ace.AceFlags & AceFlags.Inherited) != 0
                || ace.AceQualifier != AceQualifier.AccessAllowed
                || !Equals(ace.SecurityIdentifier, currentUser)
                || ace.AccessMask != (int)FileSystemRights.FullControl)
            {
                throw Failure(CredentialVaultFailure.AccessControlViolation, "凭据存储句柄包含意外权限。");
            }
        }
        finally
        {
            LocalFree(securityDescriptor);
        }
    }

    private static ByHandleFileInformation ReadHandleInformation(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据文件句柄身份无法验证。");
        }

        return information;
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
                throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据最终句柄路径无法读取。");
            }

            if (result < builder.Capacity)
            {
                var path = builder.ToString();
                if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据不能位于网络路径。");
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

        throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据最终句柄路径过长，已失败关闭。");
    }

    private DirectorySecurity CreateDirectorySecurity()
    {
        var security = new DirectorySecurity();
        ConfigureSecurity(security);
        return security;
    }

    private FileSecurity CreateFileSecurity()
    {
        var security = new FileSecurity();
        ConfigureSecurity(security);
        return security;
    }

    private void ConfigureSecurity(FileSystemSecurity security)
    {
        security.SetOwner(currentUser);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(currentUser, FileSystemRights.FullControl, AccessControlType.Allow));
    }

    private static bool PathsEqual(string left, string right)
    {
        return string.Equals(
            left.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            right.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase)
            || string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    }

    private static void EnsureExpectedIdentity(
        CredentialFileIdentity actualIdentity,
        CredentialFileIdentity expectedIdentity)
    {
        if (!PathsEqual(actualIdentity.CanonicalAbsolutePath, expectedIdentity.CanonicalAbsolutePath)
            || actualIdentity.VolumeSerialNumber != expectedIdentity.VolumeSerialNumber
            || actualIdentity.FileIndex != expectedIdentity.FileIndex)
        {
            throw Failure(CredentialVaultFailure.UnsafeFileIdentity, "凭据路径身份已发生变化，已拒绝删除。");
        }
    }

    private static string EnsureTrailingSeparator(string path)
    {
        return path.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
            ? path
            : path + Path.DirectorySeparatorChar;
    }

    private static CredentialVaultException Failure(CredentialVaultFailure failure, string message)
    {
        return new CredentialVaultException(failure, message);
    }

    private void TryDeleteVerifiedPath(string path)
    {
        try
        {
            _ = TryDeleteFile(path, expectedIdentity: null, ignoreSharingViolation: true);
        }
        catch
        {
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

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(
        IntPtr handle,
        int objectType,
        uint securityInformation,
        out IntPtr owner,
        out IntPtr group,
        out IntPtr dacl,
        out IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int fileInformationClass,
        ref FileDispositionInformation fileInformation,
        int bufferSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

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
