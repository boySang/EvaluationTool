using System;
using System.IO;
using System.Text;
using System.Threading;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Sessions;

namespace AssessmentTool.Windows.Credentials;

internal interface IPrivateKeyLeaseObserver
{
    void BuffersAllocated(char[] retrieved, byte[] encoded);

    void FileCreated(string path);

    void BeforeFailedCreationCleanup(string path);
}

internal sealed class PrivateKeyFileLeaseFactory : IPrivateKeyFileLeaseFactory
{
    internal const string ProductDirectoryName = "AssessmentTool";
    internal const string LeaseDirectoryName = "PrivateKeyLeases";
    private static readonly TimeSpan OrphanMinimumAge = TimeSpan.FromHours(24);
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
    private readonly ICredentialVault credentialVault;
    private readonly string leaseRoot;
    private readonly CredentialFileSecurity fileSecurity;
    private readonly IPrivateKeyLeaseObserver observer;

    internal PrivateKeyFileLeaseFactory(ICredentialVault credentialVault)
        : this(credentialVault, GetDefaultLeaseRoot(), new NullPrivateKeyLeaseObserver())
    {
    }

    internal PrivateKeyFileLeaseFactory(ICredentialVault credentialVault, string leaseRoot)
        : this(credentialVault, leaseRoot, new NullPrivateKeyLeaseObserver())
    {
    }

    internal PrivateKeyFileLeaseFactory(
        ICredentialVault credentialVault,
        string leaseRoot,
        IPrivateKeyLeaseObserver observer)
    {
        this.credentialVault = credentialVault ?? throw new ArgumentNullException(nameof(credentialVault));
        this.observer = observer ?? throw new ArgumentNullException(nameof(observer));
        this.leaseRoot = ValidateLeaseRoot(leaseRoot);

        var localAppData = GetLocalAppData();
        fileSecurity = new CredentialFileSecurity(localAppData);
        var productRoot = fileSecurity.ResolveUnderTrustedRoot(ProductDirectoryName);
        fileSecurity.CreateOrValidateSecureDirectory(productRoot);
        fileSecurity.CreateOrValidateSecureDirectory(this.leaseRoot);
        CleanupExpiredOrphans(DateTime.UtcNow.Subtract(OrphanMinimumAge));
    }

    public IPrivateKeyFileLease Create(
        PrivateKeyReference privateKeyReference,
        CancellationToken cancellationToken)
    {
        ValidateReference(privateKeyReference);
        cancellationToken.ThrowIfCancellationRequested();

        var runToken = Guid.NewGuid().ToString("N");
        var runDirectory = Path.Combine(leaseRoot, "run-" + runToken);
        var filePath = Path.Combine(runDirectory, "key-" + Guid.NewGuid().ToString("N") + ".ppk");
        CredentialFileIdentity? runIdentity = null;
        CredentialFileIdentity? fileIdentity = null;
        CredentialVerifiedFile? fileGuard = null;
        char[]? material = null;
        byte[]? encoded = null;
        try
        {
            fileSecurity.CreateOrValidateSecureDirectory(runDirectory);
            runIdentity = fileSecurity.GetSecureDirectoryIdentity(runDirectory);
            cancellationToken.ThrowIfCancellationRequested();

            var credentialReference = CredentialReference.Parse(privateKeyReference.ToString());
            material = credentialVault.Retrieve(credentialReference);
            PpkPrivateKeyMaterial.Validate(material);

            cancellationToken.ThrowIfCancellationRequested();
            var encodedLength = StrictUtf8.GetByteCount(material);
            encoded = new byte[encodedLength];
            _ = StrictUtf8.GetBytes(material, 0, material.Length, encoded, 0);
            observer.BuffersAllocated(material, encoded);

            using (var stream = fileSecurity.CreateSecureFile(filePath))
            {
                fileIdentity = fileSecurity.GetSecureFileIdentity(stream, filePath);
                observer.FileCreated(filePath);
                cancellationToken.ThrowIfCancellationRequested();
                stream.Write(encoded, 0, encoded.Length);
                stream.Flush(flushToDisk: true);
            }

            fileGuard = fileSecurity.OpenVerifiedRead(filePath);
            if (!fileIdentity.Value.Matches(fileGuard.Identity))
            {
                throw Failure(
                    CredentialFileLeaseFailure.StorageFailure,
                    "Plink 私钥临时文件身份在创建期间发生变化，已拒绝使用。");
            }

            cancellationToken.ThrowIfCancellationRequested();
            var lease = new PrivateKeyFileLease(
                filePath,
                "plink-private-key-" + runToken.Substring(0, 8),
                runDirectory,
                fileIdentity.Value,
                runIdentity.Value,
                fileSecurity,
                fileGuard);
            fileGuard = null;
            return lease;
        }
        catch (OperationCanceledException error)
        {
            CleanupFailedCreation(filePath, fileIdentity, runDirectory, runIdentity, fileGuard, error);
            throw;
        }
        catch (CredentialFileLeaseException error)
        {
            CleanupFailedCreation(filePath, fileIdentity, runDirectory, runIdentity, fileGuard, error);
            throw;
        }
        catch (PpkPrivateKeyException error)
        {
            CleanupFailedCreation(filePath, fileIdentity, runDirectory, runIdentity, fileGuard, error);
            throw Failure(CredentialFileLeaseFailure.InvalidCredential, error.Message);
        }
        catch (CredentialVaultException error)
        {
            CleanupFailedCreation(filePath, fileIdentity, runDirectory, runIdentity, fileGuard, error);
            throw Failure(CredentialFileLeaseFailure.StorageFailure, "无法从本机凭据库读取 Plink 私钥。");
        }
        catch (EncoderFallbackException error)
        {
            CleanupFailedCreation(filePath, fileIdentity, runDirectory, runIdentity, fileGuard, error);
            throw Failure(CredentialFileLeaseFailure.InvalidCredential, "PuTTY 私钥文本编码无效。");
        }
        catch (Exception error)
        {
            CleanupFailedCreation(filePath, fileIdentity, runDirectory, runIdentity, fileGuard, error);
            throw Failure(CredentialFileLeaseFailure.StorageFailure, "无法安全创建 Plink 私钥临时文件。");
        }
        finally
        {
            Clear(material);
            Clear(encoded);
        }
    }

    private void CleanupFailedCreation(
        string filePath,
        CredentialFileIdentity? fileIdentity,
        string runDirectory,
        CredentialFileIdentity? runIdentity,
        CredentialVerifiedFile? fileGuard,
        Exception originalFailure)
    {
        try
        {
            fileGuard?.Dispose();
            observer.BeforeFailedCreationCleanup(filePath);
            if (File.Exists(filePath))
            {
                if (!fileIdentity.HasValue)
                {
                    throw Failure(
                        CredentialFileLeaseFailure.CleanupFailure,
                        "Plink 私钥临时文件身份无法确认，已停止按路径清理。",
                        originalFailure.GetType().FullName);
                }

                fileSecurity.DeleteFile(filePath, fileIdentity.Value);
            }

            if (Directory.Exists(runDirectory))
            {
                if (!runIdentity.HasValue)
                {
                    throw Failure(
                        CredentialFileLeaseFailure.CleanupFailure,
                        "Plink 私钥临时目录身份无法确认，已停止按路径清理。",
                        originalFailure.GetType().FullName);
                }

                fileSecurity.DeleteDirectory(runDirectory, runIdentity.Value);
            }
        }
        catch (CredentialFileLeaseException error)
            when (error.Failure == CredentialFileLeaseFailure.CleanupFailure)
        {
            throw;
        }
        catch
        {
            throw Failure(
                CredentialFileLeaseFailure.CleanupFailure,
                "Plink 私钥临时文件可能残留，安全清理未能完成。",
                originalFailure.GetType().FullName);
        }
    }

    private void CleanupExpiredOrphans(DateTime notNewerThanUtc)
    {
        foreach (var runDirectory in Directory.GetDirectories(leaseRoot))
        {
            var runName = Path.GetFileName(runDirectory);
            if (!HasExactTokenName(runName, "run-", string.Empty))
            {
                continue;
            }

            var runIdentity = fileSecurity.GetSecureDirectoryIdentity(runDirectory);
            if (Directory.GetDirectories(runDirectory).Length != 0)
            {
                continue;
            }

            var files = Directory.GetFiles(runDirectory);
            if (files.Length == 0)
            {
                _ = fileSecurity.TryDeleteStaleDirectory(runDirectory, runIdentity, notNewerThanUtc);
                continue;
            }

            if (files.Length != 1
                || !HasExactTokenName(Path.GetFileName(files[0]), "key-", ".ppk")
                || !fileSecurity.TryDeleteStaleFile(files[0], notNewerThanUtc))
            {
                continue;
            }

            fileSecurity.DeleteDirectory(runDirectory, runIdentity);
        }
    }

    private static bool HasExactTokenName(string value, string prefix, string suffix)
    {
        if (!value.StartsWith(prefix, StringComparison.Ordinal)
            || !value.EndsWith(suffix, StringComparison.Ordinal)
            || value.Length != prefix.Length + 32 + suffix.Length)
        {
            return false;
        }

        var end = value.Length - suffix.Length;
        for (var index = prefix.Length; index < end; index++)
        {
            var character = value[index];
            if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
            {
                return false;
            }
        }

        return true;
    }

    private static string GetDefaultLeaseRoot()
    {
        return Path.Combine(GetLocalAppData(), ProductDirectoryName, LeaseDirectoryName);
    }

    private static string ValidateLeaseRoot(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException("Plink 私钥租约根目录不能为空。", nameof(root));
        }

        var fullRoot = Path.GetFullPath(root);
        var expectedParent = Path.Combine(GetLocalAppData(), ProductDirectoryName);
        var parent = Path.GetDirectoryName(fullRoot);
        var name = Path.GetFileName(fullRoot);
        if (!string.Equals(parent, expectedParent, StringComparison.OrdinalIgnoreCase)
            || (!string.Equals(name, LeaseDirectoryName, StringComparison.OrdinalIgnoreCase)
                && !name.StartsWith(LeaseDirectoryName + "-tests-", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(
                "Plink 私钥租约只能位于当前用户 LocalAppData 的产品专用目录。",
                nameof(root));
        }

        return fullRoot;
    }

    private static string GetLocalAppData()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData) || !Path.IsPathRooted(localAppData))
        {
            throw new InvalidOperationException("无法确定当前 Windows 用户的 LocalAppData 目录。");
        }

        return Path.GetFullPath(localAppData)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static void ValidateReference(PrivateKeyReference reference)
    {
        try
        {
            _ = reference.Value;
        }
        catch (InvalidOperationException)
        {
            throw new ArgumentException("私钥引用必须已初始化。", nameof(reference));
        }
    }

    private static CredentialFileLeaseException Failure(
        CredentialFileLeaseFailure failure,
        string message,
        string? originalFailureType = null)
    {
        return new CredentialFileLeaseException(failure, message, originalFailureType);
    }

    private static void Clear(char[]? value)
    {
        if (value != null)
        {
            Array.Clear(value, 0, value.Length);
        }
    }

    private static void Clear(byte[]? value)
    {
        if (value != null)
        {
            Array.Clear(value, 0, value.Length);
        }
    }

    private sealed class NullPrivateKeyLeaseObserver : IPrivateKeyLeaseObserver
    {
        public void BuffersAllocated(char[] retrieved, byte[] encoded)
        {
        }

        public void FileCreated(string path)
        {
        }

        public void BeforeFailedCreationCleanup(string path)
        {
        }
    }
}

internal sealed class PrivateKeyFileLease : IPrivateKeyFileLease
{
    private readonly string runDirectory;
    private readonly CredentialFileIdentity fileIdentity;
    private readonly CredentialFileIdentity runIdentity;
    private readonly CredentialFileSecurity fileSecurity;
    private readonly object cleanupSync = new object();
    private CredentialVerifiedFile? fileGuard;
    private bool disposed;

    internal PrivateKeyFileLease(
        string path,
        string redactedIdentifier,
        string runDirectory,
        CredentialFileIdentity fileIdentity,
        CredentialFileIdentity runIdentity,
        CredentialFileSecurity fileSecurity,
        CredentialVerifiedFile fileGuard)
    {
        Path = path;
        RedactedIdentifier = redactedIdentifier;
        this.runDirectory = runDirectory;
        this.fileIdentity = fileIdentity;
        this.runIdentity = runIdentity;
        this.fileSecurity = fileSecurity;
        this.fileGuard = fileGuard ?? throw new ArgumentNullException(nameof(fileGuard));
    }

    public string Path { get; }

    public string RedactedIdentifier { get; }

    public void Dispose()
    {
        lock (cleanupSync)
        {
            if (disposed)
            {
                return;
            }

            fileGuard?.Dispose();
            fileGuard = null;
            try
            {
                fileSecurity.DeleteFile(Path, fileIdentity);
                fileSecurity.DeleteDirectory(runDirectory, runIdentity);
                disposed = true;
            }
            catch (CredentialVaultException)
            {
                throw Failure("Plink 私钥临时文件未能通过身份验证并完成清理。");
            }
            catch (Exception)
            {
                throw Failure("无法安全清理 Plink 私钥临时文件。");
            }
        }
    }

    private static CredentialFileLeaseException Failure(string message)
    {
        return new CredentialFileLeaseException(CredentialFileLeaseFailure.CleanupFailure, message);
    }
}
