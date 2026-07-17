using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Credentials;
using AssessmentTool.Windows.Sessions;
using Xunit;

namespace AssessmentTool.Windows.Tests.Credentials;

public sealed class PrivateKeyFileLeaseTests
{
    [Fact]
    public void Factory_contract_accepts_only_an_opaque_private_key_reference()
    {
        var create = typeof(IPrivateKeyFileLeaseFactory).GetMethod(nameof(IPrivateKeyFileLeaseFactory.Create));

        Assert.NotNull(create);
        Assert.Equal(typeof(PrivateKeyReference), create!.GetParameters()[0].ParameterType);
        Assert.DoesNotContain(create.GetParameters(), parameter => parameter.ParameterType == typeof(string));
    }

    [Fact]
    public void Lease_writes_exact_ppk_with_private_acl_and_redacted_metadata()
    {
        using (var root = new LocalAppDataPrivateKeyRoot())
        {
            var privateKeyReference = PrivateKeyReference.New();
            var materialText = PpkPrivateKeyMaterialTests.CreatePpk(3);
            var material = materialText.ToCharArray();
            var observer = new RecordingObserver();
            var factory = new PrivateKeyFileLeaseFactory(
                new RecordingVault(privateKeyReference, material),
                root.Path,
                observer);

            using (var lease = factory.Create(privateKeyReference, CancellationToken.None))
            {
                Assert.Equal(".ppk", Path.GetExtension(lease.Path), ignoreCase: true);
                Assert.Equal(Encoding.UTF8.GetBytes(materialText), File.ReadAllBytes(lease.Path));
                Assert.DoesNotContain(privateKeyReference.ToString(), lease.Path);
                Assert.DoesNotContain(privateKeyReference.ToString(), lease.RedactedIdentifier);
                AssertCurrentUserOnly(Directory.GetAccessControl(root.Path));
                AssertCurrentUserOnly(Directory.GetAccessControl(Directory.GetParent(lease.Path)!.FullName));
                AssertCurrentUserOnly(File.GetAccessControl(lease.Path));
            }

            Assert.All(material, character => Assert.Equal('\0', character));
            Assert.NotNull(observer.Encoded);
            Assert.All(observer.Encoded!, value => Assert.Equal((byte)0, value));
            Assert.Empty(Directory.GetDirectories(root.Path));
        }
    }

    [Fact]
    public void Invalid_or_encrypted_material_never_leaves_a_temporary_file()
    {
        using (var root = new LocalAppDataPrivateKeyRoot())
        {
            var privateKeyReference = PrivateKeyReference.New();
            var material = PpkPrivateKeyMaterialTests.CreatePpk(2)
                .Replace("Encryption: none", "Encryption: aes256-cbc")
                .ToCharArray();
            var factory = new PrivateKeyFileLeaseFactory(
                new RecordingVault(privateKeyReference, material),
                root.Path);

            var exception = Assert.Throws<CredentialFileLeaseException>(
                () => factory.Create(privateKeyReference, CancellationToken.None));

            Assert.Equal(CredentialFileLeaseFailure.InvalidCredential, exception.Failure);
            Assert.All(material, character => Assert.Equal('\0', character));
            Assert.Empty(Directory.GetDirectories(root.Path));
        }
    }

    [Fact]
    public void Dispose_is_idempotent_and_removes_file_and_run_directory()
    {
        using (var root = new LocalAppDataPrivateKeyRoot())
        {
            var privateKeyReference = PrivateKeyReference.New();
            var factory = new PrivateKeyFileLeaseFactory(
                new RecordingVault(privateKeyReference, PpkPrivateKeyMaterialTests.CreatePpk(2).ToCharArray()),
                root.Path);
            var lease = factory.Create(privateKeyReference, CancellationToken.None);
            var filePath = lease.Path;
            var runDirectory = Directory.GetParent(filePath)!.FullName;

            lease.Dispose();
            lease.Dispose();

            Assert.False(File.Exists(filePath));
            Assert.False(Directory.Exists(runDirectory));
        }
    }

    [Fact]
    public void Vault_failure_is_sanitized_and_cleans_the_run_directory()
    {
        using (var root = new LocalAppDataPrivateKeyRoot())
        {
            var privateKeyReference = PrivateKeyReference.New();
            const string secret = "private-key-secret-must-not-leak";
            var factory = new PrivateKeyFileLeaseFactory(new ThrowingVault(secret), root.Path);

            var exception = Assert.Throws<CredentialFileLeaseException>(
                () => factory.Create(privateKeyReference, CancellationToken.None));

            Assert.Equal(CredentialFileLeaseFailure.StorageFailure, exception.Failure);
            Assert.DoesNotContain(secret, exception.ToString());
            Assert.Empty(Directory.GetDirectories(root.Path));
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

    private sealed class RecordingVault : ICredentialVault
    {
        private readonly CredentialReference expectedReference;
        private readonly char[] material;

        internal RecordingVault(PrivateKeyReference privateKeyReference, char[] material)
        {
            expectedReference = CredentialReference.Parse(privateKeyReference.ToString());
            this.material = material;
        }

        public CredentialReference Store(char[] secret, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public char[] Retrieve(CredentialReference reference)
        {
            Assert.Equal(expectedReference, reference);
            return material;
        }

        public void Delete(CredentialReference reference)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class ThrowingVault : ICredentialVault
    {
        private readonly string secret;

        internal ThrowingVault(string secret)
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

    private sealed class RecordingObserver : IPrivateKeyLeaseObserver
    {
        internal byte[]? Encoded { get; private set; }

        public void BuffersAllocated(char[] retrieved, byte[] encoded)
        {
            Encoded = encoded;
        }

        public void FileCreated(string path)
        {
        }

        public void BeforeFailedCreationCleanup(string path)
        {
        }
    }

    private sealed class LocalAppDataPrivateKeyRoot : IDisposable
    {
        internal LocalAppDataPrivateKeyRoot()
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            Assert.False(string.IsNullOrWhiteSpace(localAppData));
            Path = System.IO.Path.Combine(
                localAppData,
                PrivateKeyFileLeaseFactory.ProductDirectoryName,
                PrivateKeyFileLeaseFactory.LeaseDirectoryName + "-tests-" + Guid.NewGuid().ToString("N"));
        }

        internal string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
