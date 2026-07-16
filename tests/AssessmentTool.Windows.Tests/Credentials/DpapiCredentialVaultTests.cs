using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Credentials;
using Xunit;

namespace AssessmentTool.Windows.Tests.Credentials;

public sealed class DpapiCredentialVaultTests
{
    private const string Secret = "task6-secret-4e47e8d1-2341-4db3-a247-7221d9e49f72";

    [Fact]
    public void Store_returns_a_strong_reference_and_never_accepts_string_identifiers()
    {
        var store = typeof(ICredentialVault).GetMethod(nameof(ICredentialVault.Store));
        var retrieve = typeof(ICredentialVault).GetMethod(nameof(ICredentialVault.Retrieve));
        var delete = typeof(ICredentialVault).GetMethod(nameof(ICredentialVault.Delete));

        Assert.NotNull(store);
        Assert.Equal(typeof(CredentialReference), store!.ReturnType);
        Assert.DoesNotContain(store.GetParameters(), parameter => parameter.ParameterType == typeof(string));
        Assert.NotNull(retrieve);
        Assert.Equal(typeof(CredentialReference), retrieve!.GetParameters().Single().ParameterType);
        Assert.NotNull(delete);
        Assert.Equal(typeof(CredentialReference), delete!.GetParameters().Single().ParameterType);
    }

    [Fact]
    public void Stored_secret_is_encrypted_and_round_trips_for_current_user()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var secret = Secret.ToCharArray();

            var reference = vault.Store(secret);
            var retrieved = vault.Retrieve(reference);

            try
            {
                Assert.Equal(Secret, new string(retrieved));
                Assert.All(secret, character => Assert.Equal('\0', character));
                Assert.DoesNotContain(Secret, File.ReadAllText(vault.GetCredentialFilePathForTesting(reference)));
            }
            finally
            {
                Array.Clear(retrieved, 0, retrieved.Length);
            }
        }
    }

    [Fact]
    public void Different_references_retrieve_only_their_own_secret()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var first = vault.Store("first".ToCharArray());
            var second = vault.Store("second".ToCharArray());
            var firstSecret = vault.Retrieve(first);
            var secondSecret = vault.Retrieve(second);

            try
            {
                Assert.NotEqual(first, second);
                Assert.Equal("first", new string(firstSecret));
                Assert.Equal("second", new string(secondSecret));
            }
            finally
            {
                Array.Clear(firstSecret, 0, firstSecret.Length);
                Array.Clear(secondSecret, 0, secondSecret.Length);
            }
        }
    }

    [Fact]
    public void Delete_is_idempotent()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var reference = vault.Store(Secret.ToCharArray());

            vault.Delete(reference);
            vault.Delete(reference);

            var exception = Assert.Throws<CredentialVaultException>(() => vault.Retrieve(reference));
            Assert.Equal(CredentialVaultFailure.NotFound, exception.Failure);
        }
    }

    [Fact]
    public void Existing_reference_file_is_never_overwritten()
    {
        using (var folder = new TemporaryFolder())
        {
            var reference = CredentialReference.New();
            var vault = new DpapiCredentialVault(folder.Path, new FixedCredentialReferenceGenerator(reference));
            vault.Store("original".ToCharArray());

            var exception = Assert.Throws<CredentialVaultException>(() => vault.Store("replacement".ToCharArray()));

            Assert.Equal(CredentialVaultFailure.ReferenceAlreadyExists, exception.Failure);
            var retrieved = vault.Retrieve(reference);
            try
            {
                Assert.Equal("original", new string(retrieved));
            }
            finally
            {
                Array.Clear(retrieved, 0, retrieved.Length);
            }
        }
    }

    [Theory]
    [InlineData(new byte[] { 1, 2, 3 })]
    [InlineData(new byte[] { 65, 84, 67, 86, 1 })]
    public void Truncated_credential_file_fails_closed(byte[] payload)
    {
        using (var folder = new TemporaryFolder())
        {
            var reference = CredentialReference.New();
            var vault = new DpapiCredentialVault(folder.Path, new FixedCredentialReferenceGenerator(reference));
            vault.Store("fixture".ToCharArray());
            File.WriteAllBytes(vault.GetCredentialFilePathForTesting(reference), payload);

            var exception = Assert.Throws<CredentialVaultException>(() => vault.Retrieve(reference));

            Assert.Equal(CredentialVaultFailure.InvalidFile, exception.Failure);
        }
    }

    [Fact]
    public void Unknown_credential_file_version_fails_closed()
    {
        using (var folder = new TemporaryFolder())
        {
            var reference = CredentialReference.New();
            var vault = new DpapiCredentialVault(folder.Path, new FixedCredentialReferenceGenerator(reference));
            vault.Store("fixture".ToCharArray());
            File.WriteAllBytes(vault.GetCredentialFilePathForTesting(reference), new byte[]
            {
                65, 84, 67, 86, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            });

            var exception = Assert.Throws<CredentialVaultException>(() => vault.Retrieve(reference));

            Assert.Equal(CredentialVaultFailure.UnsupportedFormat, exception.Failure);
        }
    }

    [Fact]
    public void Credential_file_with_a_different_reference_fails_closed()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var actualReference = vault.Store(Secret.ToCharArray());
            var requestedReference = CredentialReference.New();
            File.Copy(vault.GetCredentialFilePathForTesting(actualReference), vault.GetCredentialFilePathForTesting(requestedReference));
            File.SetAccessControl(
                vault.GetCredentialFilePathForTesting(requestedReference),
                File.GetAccessControl(vault.GetCredentialFilePathForTesting(actualReference)));

            var exception = Assert.Throws<CredentialVaultException>(() => vault.Retrieve(requestedReference));

            Assert.Equal(CredentialVaultFailure.ReferenceMismatch, exception.Failure);
        }
    }

    [Fact]
    public void Encrypted_payload_reference_cannot_be_rebound_by_rewriting_the_outer_header()
    {
        using (var folder = new TemporaryFolder())
        {
            var firstReference = CredentialReference.New();
            var secondReference = CredentialReference.New();
            var vault = new DpapiCredentialVault(folder.Path, new FixedCredentialReferenceGenerator(firstReference));
            vault.Store(Secret.ToCharArray());
            var firstPath = vault.GetCredentialFilePathForTesting(firstReference);
            var secondPath = vault.GetCredentialFilePathForTesting(secondReference);
            var file = File.ReadAllBytes(firstPath);
            var secondReferenceBytes = secondReference.Value.ToByteArray();
            try
            {
                Buffer.BlockCopy(secondReferenceBytes, 0, file, 6, secondReferenceBytes.Length);
                File.WriteAllBytes(secondPath, file);
                File.SetAccessControl(secondPath, File.GetAccessControl(firstPath));
            }
            finally
            {
                Array.Clear(file, 0, file.Length);
                Array.Clear(secondReferenceBytes, 0, secondReferenceBytes.Length);
            }

            var exception = Assert.Throws<CredentialVaultException>(() => vault.Retrieve(secondReference));

            Assert.Equal(CredentialVaultFailure.ReferenceMismatch, exception.Failure);
            Assert.DoesNotContain(Secret, exception.ToString());
        }
    }

    [Fact]
    public void Changed_entropy_fails_closed_without_disclosing_the_secret()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var reference = vault.Store(Secret.ToCharArray());
            File.WriteAllBytes(vault.GetEntropyFilePathForTesting(), Enumerable.Repeat((byte)42, 32).ToArray());

            var exception = Assert.Throws<CredentialVaultException>(() => vault.Retrieve(reference));

            Assert.Equal(CredentialVaultFailure.CannotDecrypt, exception.Failure);
            Assert.DoesNotContain(Secret, exception.ToString());
        }
    }

    [Fact]
    public void Missing_entropy_with_existing_credentials_is_installation_data_loss_for_retrieve_and_store()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var reference = vault.Store(Secret.ToCharArray());
            File.Delete(vault.GetEntropyFilePathForTesting());

            var retrieveFailure = Assert.Throws<CredentialVaultException>(() => vault.Retrieve(reference));
            var newSecret = "new-secret".ToCharArray();
            var storeFailure = Assert.Throws<CredentialVaultException>(() => vault.Store(newSecret));

            Assert.Equal(CredentialVaultFailure.InstallationDataLost, retrieveFailure.Failure);
            Assert.Equal(CredentialVaultFailure.InstallationDataLost, storeFailure.Failure);
            Assert.False(File.Exists(vault.GetEntropyFilePathForTesting()));
            Assert.All(newSecret, character => Assert.Equal('\0', character));
        }
    }

    [Fact]
    public void First_store_without_credentials_or_entropy_initializes_the_installation()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);

            var reference = vault.Store(Secret.ToCharArray());
            var retrieved = vault.Retrieve(reference);

            try
            {
                Assert.True(File.Exists(vault.GetEntropyFilePathForTesting()));
                Assert.Equal(Secret, new string(retrieved));
            }
            finally
            {
                Array.Clear(retrieved, 0, retrieved.Length);
            }
        }
    }

    [Fact]
    public void First_operation_removes_only_vault_named_orphan_temporary_files()
    {
        using (var folder = new TemporaryFolder())
        {
            var initialVault = new DpapiCredentialVault(folder.Path);
            initialVault.Store("initial".ToCharArray());
            var credentialDirectory = initialVault.GetCredentialDirectoryPathForTesting();
            var orphan = System.IO.Path.Combine(
                credentialDirectory,
                ".atcv-" + CredentialReference.New().Value.ToString("D") + "-" + Guid.NewGuid().ToString("N") + ".tmp");
            var unrelated = System.IO.Path.Combine(credentialDirectory, ".third-party.tmp");
            CreateCurrentUserOnlyFile(orphan, "orphan");
            File.SetLastWriteTimeUtc(orphan, DateTime.UtcNow.AddDays(-2));
            File.WriteAllText(unrelated, "keep");

            var vault = new DpapiCredentialVault(folder.Path);
            vault.Store(Secret.ToCharArray());

            Assert.False(File.Exists(orphan));
            Assert.True(File.Exists(unrelated));
        }
    }

    [Fact]
    public async Task Concurrent_stores_do_not_delete_each_others_active_temporary_files()
    {
        using (var folder = new TemporaryFolder())
        using (var observer = new BlockingTemporaryFileObserver())
        {
            new DpapiCredentialVault(folder.Path).Store("initial".ToCharArray());
            var firstVault = new DpapiCredentialVault(
                folder.Path,
                new FixedCredentialReferenceGenerator(CredentialReference.New()),
                observer);
            var firstStore = Task.Run(() => firstVault.Store("first".ToCharArray()));
            Assert.True(observer.Created.Wait(TimeSpan.FromSeconds(10)));
            Assert.True(File.Exists(observer.TemporaryPath));

            var secondStore = Task.Run(() => new DpapiCredentialVault(folder.Path).Store("second".ToCharArray()));
            await Task.Delay(TimeSpan.FromMilliseconds(200));
            Assert.False(secondStore.IsCompleted);
            Assert.True(File.Exists(observer.TemporaryPath));
            observer.Release.Set();
            var firstReference = await firstStore;
            var secondReference = await secondStore;
            Assert.NotEqual(firstReference, secondReference);
        }
    }

    [Fact]
    public void Cancellation_leaves_no_temporary_credential_files()
    {
        using (var folder = new TemporaryFolder())
        using (var cancellation = new CancellationTokenSource())
        {
            var initialVault = new DpapiCredentialVault(folder.Path);
            initialVault.Store("initial".ToCharArray());
            var vault = new DpapiCredentialVault(
                folder.Path,
                new FixedCredentialReferenceGenerator(CredentialReference.New()),
                new CancelWhenTemporaryFileIsCreated(cancellation));

            Assert.Throws<OperationCanceledException>(() => vault.Store(Secret.ToCharArray(), cancellation.Token));

            Assert.Empty(Directory.GetFiles(vault.GetCredentialDirectoryPathForTesting(), "*.tmp"));
        }
    }

    [Fact]
    public void Entropy_and_credential_directory_are_restricted_to_current_user()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var reference = vault.Store(Secret.ToCharArray());

            AssertCurrentUserOnly(Directory.GetAccessControl(vault.GetCredentialDirectoryPathForTesting()));
            AssertCurrentUserOnly(File.GetAccessControl(vault.GetEntropyFilePathForTesting()));
            AssertCurrentUserOnly(File.GetAccessControl(vault.GetCredentialFilePathForTesting(reference)));
        }
    }

    [Fact]
    public void Unexpected_credential_file_ace_is_rejected_instead_of_repaired()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var reference = vault.Store(Secret.ToCharArray());
            var path = vault.GetCredentialFilePathForTesting(reference);
            var security = File.GetAccessControl(path);
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.Read,
                AccessControlType.Allow));
            File.SetAccessControl(path, security);

            var exception = Assert.Throws<CredentialVaultException>(() => vault.Retrieve(reference));

            Assert.Equal(CredentialVaultFailure.AccessControlViolation, exception.Failure);
        }
    }

    [Fact]
    public void Delete_does_not_silently_treat_access_denied_as_missing()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var reference = vault.Store(Secret.ToCharArray());
            var path = vault.GetCredentialFilePathForTesting(reference);
            var originalSecurity = File.GetAccessControl(path);
            var deniedSecurity = File.GetAccessControl(path);
            var currentUser = WindowsIdentity.GetCurrent().User;
            Assert.NotNull(currentUser);
            deniedSecurity.AddAccessRule(new FileSystemAccessRule(
                currentUser!,
                FileSystemRights.ReadAttributes,
                AccessControlType.Deny));
            File.SetAccessControl(path, deniedSecurity);
            try
            {
                var exception = Assert.Throws<CredentialVaultException>(() => vault.Delete(reference));

                Assert.Equal(CredentialVaultFailure.AccessControlViolation, exception.Failure);
                Assert.True(File.Exists(path));
            }
            finally
            {
                File.SetAccessControl(path, originalSecurity);
            }
        }
    }

    [Fact]
    public void Hardlinked_credential_file_is_rejected()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var reference = vault.Store(Secret.ToCharArray());
            var path = vault.GetCredentialFilePathForTesting(reference);
            var linkPath = System.IO.Path.Combine(folder.Path, "credential-hardlink.bin");
            Assert.True(CreateHardLink(linkPath, path, IntPtr.Zero));

            var exception = Assert.Throws<CredentialVaultException>(() => vault.Retrieve(reference));

            Assert.Equal(CredentialVaultFailure.UnsafeFileIdentity, exception.Failure);
        }
    }

    [Fact]
    public void Reparse_point_vault_root_is_rejected()
    {
        using (var folder = new TemporaryFolder())
        {
            var target = System.IO.Path.Combine(folder.Path, "target");
            var junction = System.IO.Path.Combine(folder.Path, "junction");
            Directory.CreateDirectory(target);
            CreateJunction(junction, target);
            try
            {
                var exception = Assert.Throws<CredentialVaultException>(() => new DpapiCredentialVault(junction));

                Assert.Equal(CredentialVaultFailure.UnsafeFileIdentity, exception.Failure);
            }
            finally
            {
                Directory.Delete(junction);
            }
        }
    }

    [Fact]
    public void Reparse_point_in_trusted_root_ancestor_chain_is_rejected()
    {
        using (var folder = new TemporaryFolder())
        {
            var target = System.IO.Path.Combine(folder.Path, "target");
            var targetChild = System.IO.Path.Combine(target, "trusted");
            var junction = System.IO.Path.Combine(folder.Path, "junction");
            Directory.CreateDirectory(targetChild);
            CreateJunction(junction, target);
            try
            {
                var rootBelowJunction = System.IO.Path.Combine(junction, "trusted");
                var exception = Assert.Throws<CredentialVaultException>(() => new DpapiCredentialVault(rootBelowJunction));

                Assert.Equal(CredentialVaultFailure.UnsafeFileIdentity, exception.Failure);
            }
            finally
            {
                Directory.Delete(junction);
            }
        }
    }

    [Fact]
    public void Drive_root_preserves_fully_qualified_root_semantics()
    {
        var driveRoot = System.IO.Path.GetPathRoot(System.IO.Path.GetTempPath());
        Assert.False(string.IsNullOrEmpty(driveRoot));

        var security = new CredentialFileSecurity(driveRoot!);

        Assert.Equal(driveRoot, security.TrustedRoot);
        Assert.True(System.IO.Path.IsPathRooted(security.TrustedRoot));
    }

    [Fact]
    public void Verified_read_handle_blocks_path_replacement_and_binds_identity_to_stream()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var reference = vault.Store(Secret.ToCharArray());
            var path = vault.GetCredentialFilePathForTesting(reference);
            var replacement = System.IO.Path.Combine(folder.Path, "replacement.credential");
            var security = new CredentialFileSecurity(folder.Path);

            using (var verified = security.OpenVerifiedRead(path))
            {
                Assert.True(verified.Stream.CanRead);
                Assert.Equal(path, verified.Identity.CanonicalAbsolutePath);
                Assert.Equal((uint)1, verified.Identity.LinkCount);
                Assert.ThrowsAny<IOException>(() => File.Move(path, replacement));
            }

            Assert.True(File.Exists(path));
            Assert.False(File.Exists(replacement));
        }
    }

    [Fact]
    public void Delete_uses_verified_handle_and_cannot_delete_while_another_verified_lease_is_alive()
    {
        using (var folder = new TemporaryFolder())
        {
            var vault = new DpapiCredentialVault(folder.Path);
            var reference = vault.Store(Secret.ToCharArray());
            var path = vault.GetCredentialFilePathForTesting(reference);
            var security = new CredentialFileSecurity(folder.Path);
            using (security.OpenVerifiedRead(path))
            {
                Assert.Throws<CredentialVaultException>(() => vault.Delete(reference));
                Assert.True(File.Exists(path));
            }

            vault.Delete(reference);
            Assert.False(File.Exists(path));
        }
    }

    [Theory]
    [InlineData("relative")]
    [InlineData(@"\\server\share\vault")]
    [InlineData(@"\\?\C:\vault")]
    public void Vault_rejects_untrusted_non_local_or_non_fully_qualified_roots(string root)
    {
        Assert.Throws<ArgumentException>(() => new DpapiCredentialVault(root));
    }

    private static void AssertCurrentUserOnly(FileSystemSecurity security)
    {
        var currentUser = WindowsIdentity.GetCurrent().User;
        Assert.NotNull(currentUser);
        Assert.Equal(currentUser, security.GetOwner(typeof(SecurityIdentifier)));
        Assert.True(security.AreAccessRulesProtected);
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.Single(rules);
        Assert.All(rules, rule =>
        {
            Assert.Equal(currentUser, rule.IdentityReference);
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.False(rule.IsInherited);
            Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights);
        });
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string fileName, string existingFileName, IntPtr securityAttributes);

    private static void CreateJunction(string junction, string target)
    {
        var startInfo = new ProcessStartInfo(
            "cmd.exe",
            "/d /c mklink /J \"" + junction + "\" \"" + target + "\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false
        };
        using (var process = Process.Start(startInfo))
        {
            Assert.NotNull(process);
            process!.WaitForExit();
            Assert.Equal(0, process.ExitCode);
        }
    }

    private sealed class FixedCredentialReferenceGenerator : ICredentialReferenceGenerator
    {
        private readonly CredentialReference reference;

        public FixedCredentialReferenceGenerator(CredentialReference reference)
        {
            this.reference = reference;
        }

        public CredentialReference NewReference()
        {
            return reference;
        }
    }

    private sealed class CancelWhenTemporaryFileIsCreated : ICredentialVaultWriteObserver
    {
        private readonly CancellationTokenSource cancellation;

        public CancelWhenTemporaryFileIsCreated(CancellationTokenSource cancellation)
        {
            this.cancellation = cancellation;
        }

        public void TemporaryFileCreated(string path)
        {
            cancellation.Cancel();
        }
    }

    private sealed class BlockingTemporaryFileObserver : ICredentialVaultWriteObserver, IDisposable
    {
        public ManualResetEventSlim Created { get; } = new ManualResetEventSlim();
        public ManualResetEventSlim Release { get; } = new ManualResetEventSlim();
        public string TemporaryPath { get; private set; } = string.Empty;

        public void TemporaryFileCreated(string path)
        {
            TemporaryPath = path;
            Created.Set();
            Release.Wait(TimeSpan.FromSeconds(10));
        }

        public void Dispose()
        {
            Release.Set();
            Created.Dispose();
            Release.Dispose();
        }
    }

    private static void CreateCurrentUserOnlyFile(string path, string contents)
    {
        var currentUser = WindowsIdentity.GetCurrent().User;
        Assert.NotNull(currentUser);
        var security = new FileSecurity();
        security.SetOwner(currentUser!);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(currentUser!, FileSystemRights.FullControl, AccessControlType.Allow));
        using (var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileSystemRights.FullControl,
            FileShare.None,
            4096,
            FileOptions.WriteThrough,
            security))
        using (var writer = new StreamWriter(stream))
        {
            writer.Write(contents);
        }
    }

    private sealed class TemporaryFolder : IDisposable
    {
        public TemporaryFolder()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "AssessmentTool.Task6." + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
