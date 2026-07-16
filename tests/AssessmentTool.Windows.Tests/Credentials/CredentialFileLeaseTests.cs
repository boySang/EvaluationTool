using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Credentials;
using Xunit;

namespace AssessmentTool.Windows.Tests.Credentials;

public sealed class CredentialFileLeaseTests
{
    private const string Secret = "plink-secret-凭据-7e";

    [Fact]
    public void Factory_contract_accepts_only_a_strong_credential_reference()
    {
        var create = typeof(ICredentialLeaseFactory).GetMethod(nameof(ICredentialLeaseFactory.Create));

        Assert.NotNull(create);
        Assert.Equal(typeof(CredentialReference), create!.GetParameters()[0].ParameterType);
        Assert.DoesNotContain(create.GetParameters(), parameter => parameter.ParameterType == typeof(string));
    }

    [Fact]
    public void Lease_writes_exactly_one_password_line_and_exposes_only_redacted_metadata()
    {
        using (var root = new LocalAppDataLeaseRoot())
        {
            var reference = CredentialReference.New();
            var vault = new RecordingVault(reference, Secret.ToCharArray());
            var factory = new CredentialFileLeaseFactory(vault, root.Path);

            using (var lease = factory.Create(reference, CancellationToken.None))
            {
                Assert.Equal(Encoding.UTF8.GetBytes(Secret + "\r\n"), File.ReadAllBytes(lease.Path));
                Assert.DoesNotContain(Secret, lease.Path);
                Assert.DoesNotContain(reference.ToString(), lease.Path);
                Assert.DoesNotContain(Secret, lease.RedactedIdentifier);
                Assert.DoesNotContain(reference.ToString(), lease.RedactedIdentifier);
                Assert.Equal(root.Path, Directory.GetParent(Directory.GetParent(lease.Path)!.FullName)!.FullName);
            }
        }
    }

    [Fact]
    public void Lease_directory_and_file_are_restricted_to_the_current_user()
    {
        using (var root = new LocalAppDataLeaseRoot())
        {
            var reference = CredentialReference.New();
            var factory = new CredentialFileLeaseFactory(
                new RecordingVault(reference, Secret.ToCharArray()),
                root.Path);

            using (var lease = factory.Create(reference, CancellationToken.None))
            {
                AssertCurrentUserOnly(Directory.GetAccessControl(root.Path));
                AssertCurrentUserOnly(Directory.GetAccessControl(Directory.GetParent(lease.Path)!.FullName));
                AssertCurrentUserOnly(File.GetAccessControl(lease.Path));
            }
        }
    }

    [Theory]
    [InlineData("nul\0character")]
    [InlineData("carriage\rreturn")]
    [InlineData("line\nfeed")]
    public void Password_with_control_line_characters_is_rejected_without_disclosure(string invalidSecret)
    {
        using (var root = new LocalAppDataLeaseRoot())
        {
            var reference = CredentialReference.New();
            var retrieved = invalidSecret.ToCharArray();
            var factory = new CredentialFileLeaseFactory(new RecordingVault(reference, retrieved), root.Path);

            var exception = Assert.Throws<CredentialFileLeaseException>(
                () => factory.Create(reference, CancellationToken.None));

            Assert.Equal(CredentialFileLeaseFailure.InvalidCredential, exception.Failure);
            Assert.DoesNotContain(invalidSecret, exception.ToString());
            Assert.All(retrieved, character => Assert.Equal('\0', character));
            Assert.Empty(Directory.GetDirectories(root.Path));
        }
    }

    [Fact]
    public void Dispose_removes_the_file_and_its_private_run_directory()
    {
        using (var root = new LocalAppDataLeaseRoot())
        {
            var reference = CredentialReference.New();
            var factory = new CredentialFileLeaseFactory(
                new RecordingVault(reference, Secret.ToCharArray()),
                root.Path);
            var lease = factory.Create(reference, CancellationToken.None);
            var filePath = lease.Path;
            var runDirectory = Directory.GetParent(filePath)!.FullName;

            lease.Dispose();

            Assert.False(File.Exists(filePath));
            Assert.False(Directory.Exists(runDirectory));
            Assert.True(Directory.Exists(root.Path));
        }
    }

    [Fact]
    public void Dispose_is_idempotent()
    {
        using (var root = new LocalAppDataLeaseRoot())
        {
            var reference = CredentialReference.New();
            var factory = new CredentialFileLeaseFactory(
                new RecordingVault(reference, Secret.ToCharArray()),
                root.Path);
            var lease = factory.Create(reference, CancellationToken.None);

            lease.Dispose();
            lease.Dispose();
        }
    }

    [Fact]
    public void Dispose_can_be_retried_after_a_temporary_delete_sharing_failure()
    {
        using (var root = new LocalAppDataLeaseRoot())
        {
            var reference = CredentialReference.New();
            var factory = new CredentialFileLeaseFactory(
                new RecordingVault(reference, Secret.ToCharArray()),
                root.Path);
            var lease = factory.Create(reference, CancellationToken.None);
            var filePath = lease.Path;

            using (File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var exception = Assert.Throws<CredentialFileLeaseException>(() => lease.Dispose());
                Assert.Equal(CredentialFileLeaseFailure.CleanupFailure, exception.Failure);
            }

            lease.Dispose();
            Assert.False(File.Exists(filePath));
        }
    }

    [Fact]
    public void Factory_removes_only_expired_abandoned_product_leases()
    {
        using (var root = new LocalAppDataLeaseRoot())
        {
            var reference = CredentialReference.New();
            var vault = new RecordingVault(reference, Secret.ToCharArray());
            var factory = new CredentialFileLeaseFactory(vault, root.Path);
            var abandoned = factory.Create(reference, CancellationToken.None);
            var abandonedPath = abandoned.Path;
            var abandonedDirectory = Directory.GetParent(abandonedPath)!.FullName;
            ReleaseLeaseGuardWithoutCleanup(abandoned);
            File.SetLastWriteTimeUtc(abandonedPath, DateTime.UtcNow.AddDays(-2));
            Directory.SetLastWriteTimeUtc(abandonedDirectory, DateTime.UtcNow.AddDays(-2));

            var unrelatedDirectory = System.IO.Path.Combine(root.Path, "run-not-a-product-token");
            Directory.CreateDirectory(unrelatedDirectory);
            var unrelatedFile = System.IO.Path.Combine(unrelatedDirectory, "customer-note.txt");
            File.WriteAllText(unrelatedFile, "keep");

            _ = new CredentialFileLeaseFactory(vault, root.Path);

            Assert.False(File.Exists(abandonedPath));
            Assert.False(Directory.Exists(abandonedDirectory));
            Assert.True(File.Exists(unrelatedFile));
        }
    }

    [Fact]
    public void Factory_does_not_remove_an_expired_lease_that_is_still_active()
    {
        using (var root = new LocalAppDataLeaseRoot())
        {
            var reference = CredentialReference.New();
            var vault = new RecordingVault(reference, Secret.ToCharArray());
            var factory = new CredentialFileLeaseFactory(vault, root.Path);
            using (var active = factory.Create(reference, CancellationToken.None))
            {
                AgeLeaseAndRestoreActiveGuard(active, DateTime.UtcNow.AddDays(-2));
                _ = new CredentialFileLeaseFactory(vault, root.Path);
                Assert.True(File.Exists(active.Path));
            }
        }
    }

    [Fact]
    public async Task Concurrent_leases_use_independent_directories_and_cleanup_only_themselves()
    {
        using (var root = new LocalAppDataLeaseRoot())
        {
            var vault = new ConcurrentVault();
            var factory = new CredentialFileLeaseFactory(vault, root.Path);
            var references = Enumerable.Range(0, 8).Select(_ => CredentialReference.New()).ToArray();
            foreach (var reference in references)
            {
                vault.Add(reference, Secret.ToCharArray());
            }

            var leases = await Task.WhenAll(references.Select(reference => Task.Run(
                () => factory.Create(reference, CancellationToken.None))));
            try
            {
                Assert.Equal(leases.Length, leases.Select(lease => lease.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count());
                Assert.Equal(leases.Length, leases.Select(lease => Directory.GetParent(lease.Path)!.FullName)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count());

                leases[0].Dispose();

                Assert.False(File.Exists(leases[0].Path));
                Assert.All(leases.Skip(1), lease => Assert.True(File.Exists(lease.Path)));
            }
            finally
            {
                foreach (var lease in leases)
                {
                    lease.Dispose();
                }
            }

            Assert.Empty(Directory.GetDirectories(root.Path));
        }
    }

    [Fact]
    public void Cancellation_after_file_creation_cleans_partial_artifacts_and_buffers()
    {
        using (var root = new LocalAppDataLeaseRoot())
        using (var cancellation = new CancellationTokenSource())
        {
            var reference = CredentialReference.New();
            var retrieved = Secret.ToCharArray();
            var observer = new RecordingObserver(() => cancellation.Cancel());
            var factory = new CredentialFileLeaseFactory(
                new RecordingVault(reference, retrieved),
                root.Path,
                observer);

            Assert.Throws<OperationCanceledException>(() => factory.Create(reference, cancellation.Token));

            Assert.All(retrieved, character => Assert.Equal('\0', character));
            Assert.NotNull(observer.EncodedBuffer);
            Assert.All(observer.EncodedBuffer!, value => Assert.Equal((byte)0, value));
            Assert.Empty(Directory.GetDirectories(root.Path));
        }
    }

    [Fact]
    public void Cleanup_failure_replaces_cancellation_with_a_sanitized_machine_readable_failure()
    {
        using (var root = new LocalAppDataLeaseRoot())
        using (var cancellation = new CancellationTokenSource())
        using (var observer = new IdentityReplacingObserver(cancellation))
        {
            var reference = CredentialReference.New();
            var factory = new CredentialFileLeaseFactory(
                new RecordingVault(reference, Secret.ToCharArray()),
                root.Path,
                observer);

            var exception = Assert.Throws<CredentialFileLeaseException>(
                () => factory.Create(reference, cancellation.Token));

            Assert.Equal(CredentialFileLeaseFailure.CleanupFailure, exception.Failure);
            Assert.Equal(typeof(OperationCanceledException).FullName, exception.OriginalFailureType);
            Assert.DoesNotContain(Secret, exception.ToString());
            Assert.DoesNotContain(root.Path, exception.ToString());
        }
    }

    [Fact]
    public void Retrieved_and_encoded_buffers_are_cleared_after_success()
    {
        using (var root = new LocalAppDataLeaseRoot())
        {
            var reference = CredentialReference.New();
            var retrieved = Secret.ToCharArray();
            var observer = new RecordingObserver(null);
            var factory = new CredentialFileLeaseFactory(
                new RecordingVault(reference, retrieved),
                root.Path,
                observer);

            using (factory.Create(reference, CancellationToken.None))
            {
            }

            Assert.Same(retrieved, observer.RetrievedBuffer);
            Assert.All(observer.RetrievedBuffer!, character => Assert.Equal('\0', character));
            Assert.NotNull(observer.EncodedBuffer);
            Assert.All(observer.EncodedBuffer!, value => Assert.Equal((byte)0, value));
        }
    }

    [Fact]
    public void Vault_errors_are_sanitized_before_reaching_the_session_layer()
    {
        using (var root = new LocalAppDataLeaseRoot())
        {
            var reference = CredentialReference.New();
            var factory = new CredentialFileLeaseFactory(new ThrowingVault(Secret), root.Path);

            var exception = Assert.Throws<CredentialFileLeaseException>(
                () => factory.Create(reference, CancellationToken.None));

            Assert.Equal(CredentialFileLeaseFailure.StorageFailure, exception.Failure);
            Assert.DoesNotContain(Secret, exception.ToString());
            Assert.Empty(Directory.GetDirectories(root.Path));
        }
    }

    [Fact]
    public void Factory_rejects_roots_outside_its_local_app_data_product_namespace()
    {
        var reference = CredentialReference.New();
        var vault = new RecordingVault(reference, Secret.ToCharArray());
        var rejectedRoots = new[]
        {
            Path.GetTempPath(),
            AppDomain.CurrentDomain.BaseDirectory,
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            @"\\server\share\AssessmentTool\CredentialLeases"
        }.Where(path => !string.IsNullOrWhiteSpace(path));

        foreach (var path in rejectedRoots)
        {
            Assert.Throws<ArgumentException>(() => new CredentialFileLeaseFactory(vault, path));
        }
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

    private static void ReleaseLeaseGuardWithoutCleanup(ICredentialFileLease lease)
    {
        var field = typeof(CredentialFileLease).GetField(
            "fileGuard",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(field);
        var guard = Assert.IsAssignableFrom<IDisposable>(field!.GetValue(lease));
        guard.Dispose();
    }

    private static void AgeLeaseAndRestoreActiveGuard(ICredentialFileLease lease, DateTime lastWriteTimeUtc)
    {
        var field = typeof(CredentialFileLease).GetField(
            "fileGuard",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(field);
        var previousGuard = Assert.IsAssignableFrom<IDisposable>(field!.GetValue(lease));
        previousGuard.Dispose();
        File.SetLastWriteTimeUtc(lease.Path, lastWriteTimeUtc);

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var replacementGuard = new CredentialFileSecurity(localAppData).OpenVerifiedRead(lease.Path);
        field.SetValue(lease, replacementGuard);
    }

    private sealed class RecordingVault : ICredentialVault
    {
        private readonly CredentialReference expectedReference;
        private readonly char[] secret;

        public RecordingVault(CredentialReference expectedReference, char[] secret)
        {
            this.expectedReference = expectedReference;
            this.secret = secret;
        }

        public CredentialReference Store(char[] value, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public char[] Retrieve(CredentialReference reference)
        {
            Assert.Equal(expectedReference, reference);
            return secret;
        }

        public void Delete(CredentialReference reference)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class ConcurrentVault : ICredentialVault
    {
        private readonly ConcurrentDictionary<CredentialReference, char[]> secrets =
            new ConcurrentDictionary<CredentialReference, char[]>();

        public void Add(CredentialReference reference, char[] secret)
        {
            Assert.True(secrets.TryAdd(reference, secret));
        }

        public CredentialReference Store(char[] secret, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public char[] Retrieve(CredentialReference reference)
        {
            Assert.True(secrets.TryGetValue(reference, out var secret));
            return secret!;
        }

        public void Delete(CredentialReference reference)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class ThrowingVault : ICredentialVault
    {
        private readonly string secret;

        public ThrowingVault(string secret)
        {
            this.secret = secret;
        }

        public CredentialReference Store(char[] value, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public char[] Retrieve(CredentialReference reference)
        {
            throw new CredentialVaultException(CredentialVaultFailure.StorageFailure, secret);
        }

        public void Delete(CredentialReference reference)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class RecordingObserver : ICredentialLeaseObserver
    {
        private readonly Action? onFileCreated;

        public RecordingObserver(Action? onFileCreated)
        {
            this.onFileCreated = onFileCreated;
        }

        public char[]? RetrievedBuffer { get; private set; }
        public byte[]? EncodedBuffer { get; private set; }

        public void BuffersAllocated(char[] retrieved, byte[] encoded)
        {
            RetrievedBuffer = retrieved;
            EncodedBuffer = encoded;
        }

        public void FileCreated(string path)
        {
            onFileCreated?.Invoke();
        }

        public void BeforeFailedCreationCleanup(string path)
        {
        }
    }

    private sealed class IdentityReplacingObserver : ICredentialLeaseObserver, IDisposable
    {
        private readonly CancellationTokenSource cancellation;
        private string? path;

        internal IdentityReplacingObserver(CancellationTokenSource cancellation)
        {
            this.cancellation = cancellation;
        }

        public void BuffersAllocated(char[] retrieved, byte[] encoded)
        {
        }

        public void FileCreated(string path)
        {
            this.path = path;
            cancellation.Cancel();
        }

        public void BeforeFailedCreationCleanup(string path)
        {
            Assert.Equal(this.path, path);
            File.Delete(path);
            File.WriteAllText(path, "replacement-with-a-different-file-identity");
        }

        public void Dispose()
        {
        }
    }

    private sealed class LocalAppDataLeaseRoot : IDisposable
    {
        public LocalAppDataLeaseRoot()
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            Assert.False(string.IsNullOrWhiteSpace(localAppData));
            Path = System.IO.Path.Combine(
                localAppData,
                CredentialFileLeaseFactory.ProductDirectoryName,
                CredentialFileLeaseFactory.LeaseDirectoryName + "-tests-" + Guid.NewGuid().ToString("N"));
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
