using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Windows.Credentials;

public sealed class DpapiCredentialVault : ICredentialVault
{
    private static readonly ConcurrentDictionary<string, object> OperationLocks =
        new ConcurrentDictionary<string, object>(StringComparer.OrdinalIgnoreCase);
    private static readonly byte[] FileMagic = { 65, 84, 67, 86 };
    private static readonly byte[] PayloadMagic = { 65, 84, 67, 80 };
    private const ushort FileVersion = 2;
    private const ushort PayloadVersion = 1;
    private const int EntropyLength = 32;
    private const int HeaderLength = 26;
    private const int PayloadHeaderLength = 26;
    private const int MaximumCiphertextLength = 1024 * 1024;
    private static readonly TimeSpan OrphanMinimumAge = TimeSpan.FromHours(24);
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
    private static readonly Regex CredentialFileName = new Regex(
        @"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.credential$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex CredentialTemporaryFileName = new Regex(
        @"^\.atcv-(?<reference>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-[0-9a-f]{32}\.tmp$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex EntropyTemporaryFileName = new Regex(
        @"^\.atcv-entropy-[0-9a-f]{32}\.tmp$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private readonly string credentialDirectory;
    private readonly string entropyPath;
    private readonly CredentialFileSecurity fileSecurity;
    private readonly ICredentialReferenceGenerator referenceGenerator;
    private readonly ICredentialVaultWriteObserver writeObserver;
    private readonly object operationLock;

    public DpapiCredentialVault(string trustedStorageRoot)
        : this(trustedStorageRoot, new CredentialReferenceGenerator())
    {
    }

    internal DpapiCredentialVault(string trustedStorageRoot, ICredentialReferenceGenerator referenceGenerator)
        : this(trustedStorageRoot, referenceGenerator, new NullCredentialVaultWriteObserver())
    {
    }

    internal DpapiCredentialVault(
        string trustedStorageRoot,
        ICredentialReferenceGenerator referenceGenerator,
        ICredentialVaultWriteObserver writeObserver)
    {
        this.referenceGenerator = referenceGenerator ?? throw new ArgumentNullException(nameof(referenceGenerator));
        this.writeObserver = writeObserver ?? throw new ArgumentNullException(nameof(writeObserver));
        fileSecurity = new CredentialFileSecurity(trustedStorageRoot);
        credentialDirectory = fileSecurity.ResolveUnderTrustedRoot("credentials");
        entropyPath = Path.Combine(credentialDirectory, "entropy.bin");
        operationLock = OperationLocks.GetOrAdd(credentialDirectory, _ => new object());
    }

    public CredentialReference Store(char[] secret, CancellationToken cancellationToken = default)
    {
        if (secret == null)
        {
            throw new ArgumentNullException(nameof(secret));
        }

        if (secret.Length == 0)
        {
            throw new ArgumentException("凭据不能为空。", nameof(secret));
        }

        byte[]? secretBytes = null;
        byte[]? payload = null;
        byte[]? ciphertext = null;
        byte[]? entropy = null;
        try
        {
            lock (operationLock)
            {
                cancellationToken.ThrowIfCancellationRequested();
                PrepareForStore(cancellationToken);
                entropy = ReadEntropy();
                var reference = referenceGenerator.NewReference();
                ValidateReference(reference);
                var destinationPath = GetCredentialPath(reference);
                if (File.Exists(destinationPath))
                {
                    throw Failure(CredentialVaultFailure.ReferenceAlreadyExists, "凭据引用已存在，已拒绝覆盖。");
                }

                secretBytes = StrictUtf8.GetBytes(secret);
                payload = CreateProtectedPayload(reference, secretBytes);
                ciphertext = ProtectedData.Protect(payload, entropy, DataProtectionScope.CurrentUser);
                WriteCredentialAtomically(reference, ciphertext, cancellationToken);
                return reference;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (CredentialVaultException)
        {
            throw;
        }
        catch (CryptographicException)
        {
            throw Failure(CredentialVaultFailure.StorageFailure, "凭据保护失败，请检查当前 Windows 用户配置后重试。");
        }
        catch (Exception)
        {
            throw Failure(CredentialVaultFailure.StorageFailure, "凭据保存失败，请检查本机凭据存储后重试。");
        }
        finally
        {
            Clear(secret);
            Clear(secretBytes);
            Clear(payload);
            Clear(ciphertext);
            Clear(entropy);
        }
    }

    public char[] Retrieve(CredentialReference reference)
    {
        byte[]? entropy = null;
        byte[]? ciphertext = null;
        byte[]? payload = null;
        try
        {
            lock (operationLock)
            {
                ValidateReference(reference);
                PrepareForRetrieve();
                entropy = ReadEntropy();
                ciphertext = ReadCredentialCiphertext(reference);
                payload = ProtectedData.Unprotect(ciphertext, entropy, DataProtectionScope.CurrentUser);
                return ParseProtectedPayload(reference, payload);
            }
        }
        catch (CredentialVaultException)
        {
            throw;
        }
        catch (CryptographicException)
        {
            throw Failure(CredentialVaultFailure.CannotDecrypt, "凭据无法解密。它可能属于其他 Windows 用户，或安装保护数据已发生变化。");
        }
        catch (DecoderFallbackException)
        {
            throw Failure(CredentialVaultFailure.IntegrityFailure, "凭据保护内容编码无效，已拒绝读取。");
        }
        catch (Exception)
        {
            throw Failure(CredentialVaultFailure.StorageFailure, "读取凭据失败，请检查本机凭据存储后重试。");
        }
        finally
        {
            Clear(entropy);
            Clear(ciphertext);
            Clear(payload);
        }
    }

    public void Delete(CredentialReference reference)
    {
        try
        {
            lock (operationLock)
            {
                ValidateReference(reference);
                if (!Directory.Exists(credentialDirectory))
                {
                    return;
                }

                fileSecurity.ValidateExistingSecureDirectory(credentialDirectory);
                var path = GetCredentialPath(reference);
                fileSecurity.DeleteFile(path);
            }
        }
        catch (CredentialVaultException)
        {
            throw;
        }
        catch (Exception)
        {
            throw Failure(CredentialVaultFailure.StorageFailure, "删除凭据失败，请检查本机凭据存储后重试。");
        }
    }

    internal string GetCredentialFilePathForTesting(CredentialReference reference)
    {
        return GetCredentialPath(reference);
    }

    internal string GetCredentialDirectoryPathForTesting()
    {
        return credentialDirectory;
    }

    internal string GetEntropyFilePathForTesting()
    {
        return entropyPath;
    }

    private void PrepareForStore(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        fileSecurity.CreateOrValidateSecureDirectory(credentialDirectory);
        RecoverOrphanTemporaryFiles();
        if (!File.Exists(entropyPath))
        {
            if (HasFormalCredentials())
            {
                throw InstallationDataLost();
            }

            CreateEntropyAtomically(cancellationToken);
        }

        fileSecurity.ValidateSecureFile(entropyPath, requireSingleLink: true);
    }

    private void PrepareForRetrieve()
    {
        if (!Directory.Exists(credentialDirectory))
        {
            throw Failure(CredentialVaultFailure.NotFound, "凭据存储尚未初始化。");
        }

        fileSecurity.ValidateExistingSecureDirectory(credentialDirectory);
        RecoverOrphanTemporaryFiles();
        if (!File.Exists(entropyPath))
        {
            if (HasFormalCredentials())
            {
                throw InstallationDataLost();
            }

            throw Failure(CredentialVaultFailure.NotFound, "凭据存储尚未初始化。");
        }

        fileSecurity.ValidateSecureFile(entropyPath, requireSingleLink: true);
    }

    private void CreateEntropyAtomically(CancellationToken cancellationToken)
    {
        byte[]? entropy = null;
        string? temporaryPath = null;
        try
        {
            entropy = new byte[EntropyLength];
            using (var random = RandomNumberGenerator.Create())
            {
                random.GetBytes(entropy);
            }

            temporaryPath = Path.Combine(credentialDirectory, ".atcv-entropy-" + Guid.NewGuid().ToString("N") + ".tmp");
            using (var stream = fileSecurity.CreateSecureFile(temporaryPath))
            {
                cancellationToken.ThrowIfCancellationRequested();
                stream.Write(entropy, 0, entropy.Length);
                stream.Flush(flushToDisk: true);
            }

            fileSecurity.ValidateNewlyWrittenFile(temporaryPath);
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryPath, entropyPath);
            temporaryPath = null;
            fileSecurity.ValidateNewlyWrittenFile(entropyPath);
        }
        catch (IOException) when (File.Exists(entropyPath))
        {
            fileSecurity.ValidateSecureFile(entropyPath, requireSingleLink: true);
        }
        finally
        {
            Clear(entropy);
            CleanupTemporaryFile(temporaryPath);
        }
    }

    private byte[] ReadEntropy()
    {
        using (var verified = fileSecurity.OpenVerifiedRead(entropyPath))
        {
            var stream = verified.Stream;
            if (stream.Length != EntropyLength)
            {
                throw Failure(CredentialVaultFailure.IntegrityFailure, "安装保护数据无效，已拒绝读取。");
            }

            var entropy = new byte[EntropyLength];
            ReadExactly(stream, entropy, 0, entropy.Length);
            return entropy;
        }
    }

    private void WriteCredentialAtomically(CredentialReference reference, byte[] ciphertext, CancellationToken cancellationToken)
    {
        if (ciphertext == null || ciphertext.Length == 0 || ciphertext.Length > MaximumCiphertextLength)
        {
            throw Failure(CredentialVaultFailure.StorageFailure, "凭据保护结果无效，已拒绝保存。");
        }

        var destinationPath = GetCredentialPath(reference);
        if (File.Exists(destinationPath))
        {
            throw Failure(CredentialVaultFailure.ReferenceAlreadyExists, "凭据引用已存在，已拒绝覆盖。");
        }

        string? temporaryPath = null;
        byte[]? header = null;
        try
        {
            temporaryPath = Path.Combine(
                credentialDirectory,
                ".atcv-" + reference.Value.ToString("D") + "-" + Guid.NewGuid().ToString("N") + ".tmp");
            header = CreateOuterHeader(reference, ciphertext.Length);
            using (var stream = fileSecurity.CreateSecureFile(temporaryPath))
            {
                writeObserver.TemporaryFileCreated(temporaryPath);
                cancellationToken.ThrowIfCancellationRequested();
                stream.Write(header, 0, header.Length);
                stream.Write(ciphertext, 0, ciphertext.Length);
                stream.Flush(flushToDisk: true);
            }

            fileSecurity.ValidateNewlyWrittenFile(temporaryPath);
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                File.Move(temporaryPath, destinationPath);
                temporaryPath = null;
            }
            catch (IOException) when (File.Exists(destinationPath))
            {
                throw Failure(CredentialVaultFailure.ReferenceAlreadyExists, "凭据引用已存在，已拒绝覆盖。");
            }

            fileSecurity.ValidateNewlyWrittenFile(destinationPath);
        }
        finally
        {
            Clear(header);
            CleanupTemporaryFile(temporaryPath);
        }
    }

    private byte[] ReadCredentialCiphertext(CredentialReference expectedReference)
    {
        var path = GetCredentialPath(expectedReference);
        if (!File.Exists(path))
        {
            throw Failure(CredentialVaultFailure.NotFound, "未找到指定凭据。请重新录入凭据后重试。");
        }

        try
        {
            using (var verified = fileSecurity.OpenVerifiedRead(path))
            using (var reader = new BinaryReader(verified.Stream, Encoding.UTF8, leaveOpen: false))
            {
                var stream = verified.Stream;
                if (stream.Length < HeaderLength)
                {
                    throw Failure(CredentialVaultFailure.InvalidFile, "凭据文件不完整，已拒绝读取。");
                }

                var magic = ReadExactly(reader, FileMagic.Length);
                try
                {
                    if (!FixedTimeEquals(magic, FileMagic))
                    {
                        throw Failure(CredentialVaultFailure.InvalidFile, "凭据文件格式无效，已拒绝读取。");
                    }
                }
                finally
                {
                    Clear(magic);
                }

                var version = reader.ReadUInt16();
                if (version != FileVersion)
                {
                    throw Failure(CredentialVaultFailure.UnsupportedFormat, "凭据文件版本不受支持，已拒绝读取。");
                }

                var referenceBytes = ReadExactly(reader, 16);
                try
                {
                    var requestedReferenceBytes = expectedReference.Value.ToByteArray();
                    try
                    {
                        if (!FixedTimeEquals(referenceBytes, requestedReferenceBytes))
                        {
                            throw Failure(CredentialVaultFailure.ReferenceMismatch, "凭据文件与请求的凭据引用不匹配，已拒绝读取。");
                        }
                    }
                    finally
                    {
                        Clear(requestedReferenceBytes);
                    }
                }
                finally
                {
                    Clear(referenceBytes);
                }

                var ciphertextLength = reader.ReadInt32();
                if (ciphertextLength <= 0
                    || ciphertextLength > MaximumCiphertextLength
                    || stream.Length != HeaderLength + ciphertextLength)
                {
                    throw Failure(CredentialVaultFailure.InvalidFile, "凭据文件长度无效，已拒绝读取。");
                }

                return ReadExactly(reader, ciphertextLength);
            }
        }
        catch (CredentialVaultException)
        {
            throw;
        }
        catch (EndOfStreamException)
        {
            throw Failure(CredentialVaultFailure.InvalidFile, "凭据文件不完整，已拒绝读取。");
        }
        catch (IOException)
        {
            throw Failure(CredentialVaultFailure.InvalidFile, "凭据文件无法安全读取，已拒绝使用。");
        }
    }

    private static byte[] CreateProtectedPayload(CredentialReference reference, byte[] secretBytes)
    {
        if (secretBytes.Length == 0 || secretBytes.Length > MaximumCiphertextLength - PayloadHeaderLength)
        {
            throw Failure(CredentialVaultFailure.StorageFailure, "凭据长度超出允许范围。");
        }

        var payload = new byte[PayloadHeaderLength + secretBytes.Length];
        Buffer.BlockCopy(PayloadMagic, 0, payload, 0, PayloadMagic.Length);
        WriteUInt16(payload, 4, PayloadVersion);
        var referenceBytes = reference.Value.ToByteArray();
        try
        {
            Buffer.BlockCopy(referenceBytes, 0, payload, 6, referenceBytes.Length);
        }
        finally
        {
            Clear(referenceBytes);
        }

        WriteInt32(payload, 22, secretBytes.Length);
        Buffer.BlockCopy(secretBytes, 0, payload, PayloadHeaderLength, secretBytes.Length);
        return payload;
    }

    private static char[] ParseProtectedPayload(CredentialReference expectedReference, byte[] payload)
    {
        if (payload.Length < PayloadHeaderLength)
        {
            throw Failure(CredentialVaultFailure.IntegrityFailure, "凭据保护内容不完整，已拒绝读取。");
        }

        if (!FixedTimeEquals(payload, 0, PayloadMagic, 0, PayloadMagic.Length))
        {
            throw Failure(CredentialVaultFailure.IntegrityFailure, "凭据保护内容格式无效，已拒绝读取。");
        }

        if (ReadUInt16(payload, 4) != PayloadVersion)
        {
            throw Failure(CredentialVaultFailure.UnsupportedFormat, "凭据保护内容版本不受支持，已拒绝读取。");
        }

        var expectedReferenceBytes = expectedReference.Value.ToByteArray();
        try
        {
            if (!FixedTimeEquals(payload, 6, expectedReferenceBytes, 0, expectedReferenceBytes.Length))
            {
                throw Failure(CredentialVaultFailure.ReferenceMismatch, "加密凭据与请求的凭据引用不匹配，已拒绝读取。");
            }
        }
        finally
        {
            Clear(expectedReferenceBytes);
        }

        var secretLength = ReadInt32(payload, 22);
        if (secretLength <= 0 || secretLength != payload.Length - PayloadHeaderLength)
        {
            throw Failure(CredentialVaultFailure.IntegrityFailure, "凭据保护内容长度无效，已拒绝读取。");
        }

        return StrictUtf8.GetChars(payload, PayloadHeaderLength, secretLength);
    }

    private void RecoverOrphanTemporaryFiles()
    {
        foreach (var path in Directory.EnumerateFiles(credentialDirectory, ".atcv-*.tmp", SearchOption.TopDirectoryOnly))
        {
            var name = Path.GetFileName(path);
            var credentialMatch = CredentialTemporaryFileName.Match(name);
            var isCredentialOrphan = credentialMatch.Success
                && !File.Exists(Path.Combine(credentialDirectory, credentialMatch.Groups["reference"].Value + ".credential"));
            var isEntropyOrphan = EntropyTemporaryFileName.IsMatch(name) && !File.Exists(entropyPath);
            if (isCredentialOrphan || isEntropyOrphan)
            {
                try
                {
                    _ = fileSecurity.TryDeleteStaleFile(path, DateTime.UtcNow - OrphanMinimumAge);
                }
                catch (Exception)
                {
                    throw Failure(CredentialVaultFailure.RecoveryFailure, "凭据存储临时文件恢复失败。");
                }
            }
        }
    }

    private bool HasFormalCredentials()
    {
        foreach (var path in Directory.EnumerateFiles(credentialDirectory, "*.credential", SearchOption.TopDirectoryOnly))
        {
            if (CredentialFileName.IsMatch(Path.GetFileName(path)))
            {
                return true;
            }
        }

        return false;
    }

    private string GetCredentialPath(CredentialReference reference)
    {
        ValidateReference(reference);
        return Path.Combine(credentialDirectory, reference.Value.ToString("D") + ".credential");
    }

    private static byte[] CreateOuterHeader(CredentialReference reference, int ciphertextLength)
    {
        var header = new byte[HeaderLength];
        Buffer.BlockCopy(FileMagic, 0, header, 0, FileMagic.Length);
        WriteUInt16(header, 4, FileVersion);
        var referenceBytes = reference.Value.ToByteArray();
        try
        {
            Buffer.BlockCopy(referenceBytes, 0, header, 6, referenceBytes.Length);
        }
        finally
        {
            Clear(referenceBytes);
        }

        WriteInt32(header, 22, ciphertextLength);
        return header;
    }

    private void CleanupTemporaryFile(string? path)
    {
        if (path == null)
        {
            return;
        }

        try
        {
            fileSecurity.DeleteFile(path);
        }
        catch (Exception)
        {
            throw Failure(CredentialVaultFailure.RecoveryFailure, "凭据临时文件清理失败。");
        }
    }

    private static byte[] ReadExactly(BinaryReader reader, int count)
    {
        var bytes = reader.ReadBytes(count);
        if (bytes.Length != count)
        {
            Clear(bytes);
            throw new EndOfStreamException();
        }

        return bytes;
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count)
    {
        var total = 0;
        while (total < count)
        {
            var read = stream.Read(buffer, offset + total, count - total);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }

            total += read;
        }
    }

    private static bool FixedTimeEquals(byte[] left, byte[] right)
    {
        return FixedTimeEquals(left, 0, right, 0, left.Length) && left.Length == right.Length;
    }

    private static bool FixedTimeEquals(byte[] left, int leftOffset, byte[] right, int rightOffset, int count)
    {
        if (leftOffset < 0
            || rightOffset < 0
            || count < 0
            || left.Length - leftOffset < count
            || right.Length - rightOffset < count)
        {
            return false;
        }

        var difference = 0;
        for (var index = 0; index < count; index++)
        {
            difference |= left[leftOffset + index] ^ right[rightOffset + index];
        }

        return difference == 0;
    }

    private static void WriteUInt16(byte[] buffer, int offset, ushort value)
    {
        buffer[offset] = (byte)(value & 0xff);
        buffer[offset + 1] = (byte)(value >> 8);
    }

    private static ushort ReadUInt16(byte[] buffer, int offset)
    {
        return (ushort)(buffer[offset] | (buffer[offset + 1] << 8));
    }

    private static void WriteInt32(byte[] buffer, int offset, int value)
    {
        buffer[offset] = (byte)value;
        buffer[offset + 1] = (byte)(value >> 8);
        buffer[offset + 2] = (byte)(value >> 16);
        buffer[offset + 3] = (byte)(value >> 24);
    }

    private static int ReadInt32(byte[] buffer, int offset)
    {
        return buffer[offset]
            | (buffer[offset + 1] << 8)
            | (buffer[offset + 2] << 16)
            | (buffer[offset + 3] << 24);
    }

    private static void ValidateReference(CredentialReference reference)
    {
        try
        {
            _ = reference.Value;
        }
        catch (InvalidOperationException)
        {
            throw new ArgumentException("凭据引用必须是有效的 GUID。", nameof(reference));
        }
    }

    private static CredentialVaultException InstallationDataLost()
    {
        return Failure(
            CredentialVaultFailure.InstallationDataLost,
            "安装保护数据已丢失，现有凭据无法恢复。请重新录入凭据；软件不会静默创建新的保护数据。");
    }

    private static CredentialVaultException Failure(CredentialVaultFailure failure, string message)
    {
        return new CredentialVaultException(failure, message);
    }

    private static void Clear(byte[]? value)
    {
        if (value != null)
        {
            Array.Clear(value, 0, value.Length);
        }
    }

    private static void Clear(char[]? value)
    {
        if (value != null)
        {
            Array.Clear(value, 0, value.Length);
        }
    }

    private sealed class CredentialReferenceGenerator : ICredentialReferenceGenerator
    {
        public CredentialReference NewReference()
        {
            return CredentialReference.New();
        }
    }

    private sealed class NullCredentialVaultWriteObserver : ICredentialVaultWriteObserver
    {
        public void TemporaryFileCreated(string path)
        {
        }
    }
}
