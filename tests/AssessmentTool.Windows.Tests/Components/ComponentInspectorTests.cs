using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Windows.Components;
using Xunit;

namespace AssessmentTool.Windows.Tests.Components;

public sealed class ComponentInspectorTests
{
    private const string ExpectedHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string MinimumVersion = "0.84.0.0";

    [Fact]
    public void Trusted_catalog_exposes_only_the_fixed_read_only_plink_definition()
    {
        var plink = TrustedComponentCatalog.Plink;

        Assert.Same(plink, TrustedComponentCatalog.Plink);
        Assert.Equal("plink", plink.Id);
        Assert.Equal(@"依赖组件\plink.exe", plink.TrustedRelativePath);
        Assert.Equal("e5621ffe4879f0ec39ed40f688db9399c2d43054d41ef14472fa335c4693b915", plink.ExpectedSha256);
        Assert.Equal("0.84.0.0", plink.MinimumVersion);
        Assert.Equal(ComponentArchitecture.X64, plink.RequiredArchitecture);
        Assert.Equal("SSH连接", plink.AffectedFeature);

        var catalogType = typeof(TrustedComponentCatalog);
        Assert.True(catalogType.IsPublic && catalogType.IsAbstract && catalogType.IsSealed);
        var property = catalogType.GetProperty(nameof(TrustedComponentCatalog.Plink), BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(property);
        Assert.True(property!.CanRead);
        Assert.False(property.CanWrite);
        Assert.Equal(typeof(ComponentDefinition), property.PropertyType);
        Assert.Empty(typeof(ComponentDefinition).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(
            typeof(ComponentDefinition).GetMethods(BindingFlags.Public | BindingFlags.Static),
            method => method.ReturnType == typeof(ComponentDefinition));
    }

    [Fact]
    public void Missing_plink_reports_impact_and_offline_remediation()
    {
        var inspector = CreateInspector(new FakeFileSystem(false));

        var status = inspector.Inspect(ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion));

        Assert.False(status.Available);
        Assert.Equal(ComponentFailure.Missing, status.Failure);
        Assert.Equal("SSH连接", status.AffectedFeature);
        Assert.Contains("依赖组件", status.OfflineInstructions);
        Assert.True(status.RequiresUserConfirmationBeforeInstall);
        Assert.False(status.AutomaticallyInstalls);
        Assert.Null(status.VerifiedIdentity);
    }

    [Fact]
    public void Hash_mismatch_disables_only_the_component_feature()
    {
        var inspector = CreateInspector(new FakeFileSystem(true), hash: new FakeHashReader(ExpectedHash.Replace('0', 'f')));

        var status = inspector.Inspect(ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion));

        Assert.False(status.Available);
        Assert.Equal(ComponentFailure.HashMismatch, status.Failure);
        Assert.Contains("SSH连接", status.UserImpact);
    }

    [Fact]
    public void Version_lower_than_required_is_rejected_strictly()
    {
        var inspector = CreateInspector(new FakeFileSystem(true), version: new FakeVersionReader("0.83.0.0"));

        var status = inspector.Inspect(ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion));

        Assert.False(status.Available);
        Assert.Equal(ComponentFailure.VersionTooLow, status.Failure);
    }

    [Fact]
    public void Component_with_wrong_binary_architecture_is_rejected()
    {
        var inspector = CreateInspector(new FakeFileSystem(true), architecture: new FakeArchitectureReader(ComponentArchitecture.X86));

        var status = inspector.Inspect(ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion));

        Assert.False(status.Available);
        Assert.Equal(ComponentFailure.ArchitectureMismatch, status.Failure);
    }

    [Fact]
    public void File_identity_changed_during_single_handle_inspection_fails_closed()
    {
        var fileSystem = new FakeFileSystem(true) { ChangeSnapshotDuringRead = true };

        var status = CreateInspector(fileSystem).Inspect(ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion));

        Assert.False(status.Available);
        Assert.Equal(ComponentFailure.FileChangedDuringInspection, status.Failure);
    }

    [Fact]
    public void Verified_component_status_carries_diagnostic_handle_identity()
    {
        var status = CreateInspector(new FakeFileSystem(true)).Inspect(
            ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion));

        Assert.True(status.Available);
        Assert.Equal(ComponentFailure.None, status.Failure);
        Assert.NotNull(status.VerifiedIdentity);
        Assert.Equal(ExpectedHash, status.VerifiedIdentity!.Sha256);
        Assert.Equal(10, status.VerifiedIdentity.Length);
        Assert.Equal((uint)123, status.VerifiedIdentity.VolumeSerialNumber);
        Assert.Equal((ulong)456, status.VerifiedIdentity.FileIndex);
        Assert.Contains("诊断", status.UserImpact);
    }

    [Fact]
    public void Execution_revalidation_reopens_and_compares_identity_and_hash()
    {
        var fileSystem = new FakeFileSystem(true);
        var inspector = CreateInspector(fileSystem);
        var definition = ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion);
        var status = inspector.Inspect(definition);

        using (var candidate = inspector.RevalidateForExecution(definition, status))
        {
            Assert.Equal(2, fileSystem.OpenCount);
            Assert.Equal(1, fileSystem.ActiveHandleCount);
            Assert.Equal(2, fileSystem.ActiveDirectoryHandleCount);
            Assert.Equal(status.VerifiedIdentity!.FileIndex, candidate.VerifiedIdentity.FileIndex);
            Assert.True(candidate.WasRevalidatedForExecution);
            Assert.True(fileSystem.ReplacementIsBlocked);
            candidate.LaunchWhileLocked(path =>
            {
                Assert.Equal(@"C:\AssessmentTool\tools\plink.exe", path);
                Assert.Equal(1, fileSystem.ActiveHandleCount);
                Assert.Equal(2, fileSystem.ActiveDirectoryHandleCount);
                Assert.True(fileSystem.ReplacementIsBlocked);
            });
        }

        Assert.Equal(0, fileSystem.ActiveHandleCount);
        Assert.Equal(0, fileSystem.ActiveDirectoryHandleCount);
    }

    [Fact]
    public void Execution_revalidation_rejects_replaced_file_even_when_available_was_true()
    {
        var fileSystem = new FakeFileSystem(true) { ChangeIdentityOnSecondOpen = true };
        var inspector = CreateInspector(fileSystem);
        var definition = ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion);
        var status = inspector.Inspect(definition);

        var exception = Assert.Throws<ComponentExecutionValidationException>(() =>
            inspector.RevalidateForExecution(definition, status));

        Assert.Contains("重新验证", exception.Message);
        Assert.Equal(2, fileSystem.OpenCount);
    }

    [Theory]
    [InlineData(@"tools\plink.exe:evil")]
    [InlineData(@"tools\CON.exe")]
    [InlineData(@"tools\plink.exe.")]
    [InlineData("tools\\plink.exe ")]
    [InlineData(@"..\plink.exe")]
    [InlineData(@"\\server\share\plink.exe")]
    public void Component_definition_rejects_unsafe_relative_paths(string path)
    {
        Assert.Throws<ArgumentException>(() => ComponentDefinition.Plink(path, ExpectedHash, MinimumVersion));
    }

    [Fact]
    public void Plink_requires_an_explicit_strict_minimum_version()
    {
        var plinkMethods = typeof(ComponentDefinition).GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
            .Where(method => method.Name == nameof(ComponentDefinition.Plink))
            .ToArray();

        Assert.Single(plinkMethods);
        Assert.Equal(3, plinkMethods[0].GetParameters().Length);
        Assert.False(plinkMethods[0].GetParameters()[2].HasDefaultValue);
        Assert.Throws<ArgumentException>(() => ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, "0.84"));
    }

    [Fact]
    public void Strict_pe_reader_requires_machine_and_optional_header_magic_to_agree()
    {
        var reader = new PeComponentArchitectureReader();
        using (var stream = CreatePe(machine: 0x8664, optionalMagic: 0x010b, optionalHeaderSize: 240))
        {
            Assert.Throws<InvalidDataException>(() => reader.ReadArchitecture(stream));
        }
    }

    [Fact]
    public void Strict_pe_reader_rejects_arm64_explicitly()
    {
        var reader = new PeComponentArchitectureReader();
        using (var stream = CreatePe(machine: 0xaa64, optionalMagic: 0x020b, optionalHeaderSize: 240))
        {
            Assert.Throws<InvalidDataException>(() => reader.ReadArchitecture(stream));
        }
    }

    [Fact]
    public void Dependency_injection_and_available_status_construction_are_internal_only()
    {
        Assert.False(typeof(IComponentFileSystem).IsPublic);
        Assert.False(typeof(IComponentFileHandle).IsPublic);
        Assert.False(typeof(IComponentVersionReader).IsPublic);
        Assert.False(typeof(IComponentArchitectureReader).IsPublic);
        Assert.False(typeof(IComponentHashReader).IsPublic);
        Assert.Empty(typeof(ComponentStatus).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(ComponentExecutionCandidate).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(ComponentDefinition).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(typeof(ComponentDefinition).GetMethods(BindingFlags.Public | BindingFlags.Static), method =>
            method.Name == nameof(ComponentDefinition.Plink));
        Assert.Contains(typeof(ComponentInspector).GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance), constructor =>
            constructor.GetParameters().Any(parameter => parameter.ParameterType == typeof(IComponentFileSystem)));
    }

    [Fact]
    public void Version_reader_receives_the_same_live_locked_handle_used_for_hash_and_identity()
    {
        var fileSystem = new FakeFileSystem(true);
        var versionReader = new FakeVersionReader(
            MinimumVersion,
            () => fileSystem.ActiveHandleCount,
            () => fileSystem.ActiveDirectoryHandleCount);

        var status = CreateInspector(fileSystem, version: versionReader).Inspect(
            ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion));

        Assert.True(status.Available);
        Assert.Equal(1, versionReader.ActiveHandlesObserved);
        Assert.Equal(2, versionReader.ActiveDirectoryHandlesObserved);
        Assert.Equal(0, fileSystem.ActiveHandleCount);
        Assert.Equal(0, fileSystem.ActiveDirectoryHandleCount);
    }

    [Fact]
    public void Physical_execution_candidate_blocks_replacement_until_disposed()
    {
        using (var folder = new TemporaryFolder())
        {
            var source = typeof(ComponentInspector).Assembly.Location;
            var toolsPath = Path.Combine(folder.Path, "tools");
            Directory.CreateDirectory(toolsPath);
            var candidatePath = Path.Combine(toolsPath, "candidate.dll");
            var replacementPath = Path.Combine(folder.Path, "replacement.dll");
            var movedToolsPath = Path.Combine(folder.Path, "moved-tools");
            File.Copy(source, candidatePath);
            var hash = ComputeSha256(candidatePath);
            var version = FileVersionInfo.GetVersionInfo(candidatePath).FileVersion;
            Assert.True(ComponentDefinition.TryParseStrictVersion(version, out _));
            ComponentArchitecture architecture;
            using (var stream = File.OpenRead(candidatePath))
            {
                architecture = new PeComponentArchitectureReader().ReadArchitecture(stream);
            }

            var definition = new ComponentDefinition(
                "test-component",
                @"tools\candidate.dll",
                hash,
                version!,
                architecture,
                "测试组件");
            var inspector = new ComponentInspector(folder.Path);
            var status = inspector.Inspect(definition);

            using (var candidate = inspector.RevalidateForExecution(definition, status))
            {
                candidate.LaunchWhileLocked(path =>
                {
                    Assert.Equal(candidatePath, path);
                    Assert.ThrowsAny<IOException>(() => File.Move(candidatePath, replacementPath));
                    Assert.ThrowsAny<IOException>(() => Directory.Move(toolsPath, movedToolsPath));
                    Assert.True(File.Exists(candidatePath));
                });
            }

            Directory.Move(toolsPath, movedToolsPath);
            Assert.True(File.Exists(Path.Combine(movedToolsPath, "candidate.dll")));
        }
    }

    [Fact]
    public void Disposed_execution_candidate_rejects_launch_and_exposes_no_path_or_handle_property()
    {
        var fileSystem = new FakeFileSystem(true);
        var inspector = CreateInspector(fileSystem);
        var definition = ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion);
        var candidate = inspector.RevalidateForExecution(definition, inspector.Inspect(definition));

        candidate.Dispose();

        Assert.Throws<ObjectDisposedException>(() => candidate.LaunchWhileLocked(_ => { }));
        var launchMethod = typeof(ComponentExecutionCandidate).GetMethod(
            "LaunchWhileLocked",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(launchMethod);
        Assert.Equal(typeof(void), launchMethod!.ReturnType);
        Assert.DoesNotContain(
            typeof(ComponentExecutionCandidate).GetProperties(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance),
            property => property.Name.IndexOf("Path", StringComparison.OrdinalIgnoreCase) >= 0
                || property.Name.IndexOf("Handle", StringComparison.OrdinalIgnoreCase) >= 0
                || property.PropertyType == typeof(IComponentFileHandle));
        Assert.Null(typeof(ComponentFileIdentity).GetProperty(
            "CanonicalAbsolutePath",
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance));
    }

    [Fact]
    public void Reentrant_dispose_during_launch_is_rejected_without_releasing_lease()
    {
        var fileSystem = new FakeFileSystem(true);
        var inspector = CreateInspector(fileSystem);
        var definition = ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion);
        var candidate = inspector.RevalidateForExecution(definition, inspector.Inspect(definition));

        candidate.LaunchWhileLocked(_ =>
        {
            Assert.Throws<InvalidOperationException>(() => candidate.Dispose());
            Assert.True(fileSystem.ReplacementIsBlocked);
            Assert.Equal(1, fileSystem.ActiveHandleCount);
            Assert.Equal(2, fileSystem.ActiveDirectoryHandleCount);
        });

        Assert.True(fileSystem.ReplacementIsBlocked);
        candidate.Dispose();
        Assert.False(fileSystem.ReplacementIsBlocked);
    }

    [Fact]
    public async Task Concurrent_dispose_waits_for_launch_callback_before_releasing_lease()
    {
        var fileSystem = new FakeFileSystem(true);
        var inspector = CreateInspector(fileSystem);
        var definition = ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion);
        var candidate = inspector.RevalidateForExecution(definition, inspector.Inspect(definition));
        using (var entered = new ManualResetEventSlim())
        using (var release = new ManualResetEventSlim())
        {
            var launch = Task.Run(() => candidate.LaunchWhileLocked(_ =>
            {
                entered.Set();
                release.Wait(TimeSpan.FromSeconds(10));
            }));
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
            var dispose = Task.Run(() => candidate.Dispose());

            await Task.Delay(TimeSpan.FromMilliseconds(200));
            Assert.False(dispose.IsCompleted);
            Assert.True(fileSystem.ReplacementIsBlocked);

            release.Set();
            await launch;
            await dispose;
            Assert.False(fileSystem.ReplacementIsBlocked);
        }
    }

    [Fact]
    public void Physical_component_reader_rejects_a_junction_parent()
    {
        using (var folder = new TemporaryFolder())
        {
            var target = Path.Combine(folder.Path, "target");
            var tools = Path.Combine(folder.Path, "tools");
            Directory.CreateDirectory(target);
            File.WriteAllBytes(Path.Combine(target, "plink.exe"), new byte[] { 1, 2, 3 });
            CreateJunction(tools, target);
            try
            {
                var fileSystem = new PhysicalComponentFileSystem();
                var trustedRoot = fileSystem.ValidateTrustedRoot(folder.Path);
                var candidate = fileSystem.ResolveTrustedPath(trustedRoot, @"tools\plink.exe");

                Assert.Throws<InvalidDataException>(() => fileSystem.OpenRead(trustedRoot, candidate));
            }
            finally
            {
                Directory.Delete(tools);
            }
        }
    }

    [Fact]
    public void Dtos_are_immutable_and_require_a_64_character_hex_hash()
    {
        var definition = ComponentDefinition.Plink(@"tools\plink.exe", ExpectedHash, MinimumVersion);
        var status = CreateInspector(new FakeFileSystem(false)).Inspect(definition);

        Assert.All(typeof(ComponentDefinition).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.All(typeof(ComponentStatus).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.All(typeof(ComponentFileIdentity).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.Null(typeof(ComponentFileIdentity).GetProperty(
            "CanonicalAbsolutePath",
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance));
        Assert.Throws<ArgumentException>(() => ComponentDefinition.Plink(@"tools\plink.exe", "ABC", MinimumVersion));
        Assert.Contains("不会自动安装", status.OfflineInstructions);
    }

    private static ComponentInspector CreateInspector(
        FakeFileSystem fileSystem,
        IComponentVersionReader? version = null,
        IComponentArchitectureReader? architecture = null,
        IComponentHashReader? hash = null)
    {
        return new ComponentInspector(
            @"C:\AssessmentTool",
            fileSystem,
            version ?? new FakeVersionReader(MinimumVersion),
            architecture ?? new FakeArchitectureReader(ComponentArchitecture.X64),
            hash ?? new FakeHashReader(ExpectedHash));
    }

    private static MemoryStream CreatePe(ushort machine, ushort optionalMagic, ushort optionalHeaderSize)
    {
        var bytes = new byte[512];
        bytes[0] = 0x4d;
        bytes[1] = 0x5a;
        bytes[0x3c] = 0x80;
        bytes[0x80] = 0x50;
        bytes[0x81] = 0x45;
        bytes[0x84] = (byte)machine;
        bytes[0x85] = (byte)(machine >> 8);
        bytes[0x86] = 1;
        bytes[0x94] = (byte)optionalHeaderSize;
        bytes[0x95] = (byte)(optionalHeaderSize >> 8);
        bytes[0x98] = (byte)optionalMagic;
        bytes[0x99] = (byte)(optionalMagic >> 8);
        return new MemoryStream(bytes, writable: false);
    }

    private static string ComputeSha256(string path)
    {
        using (var stream = File.OpenRead(path))
        using (var hash = SHA256.Create())
        {
            return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", string.Empty).ToLowerInvariant();
        }
    }

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

    private sealed class TemporaryFolder : IDisposable
    {
        public TemporaryFolder()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "AssessmentTool.Component.Task6." + Guid.NewGuid().ToString("N"));
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

    private sealed class FakeFileSystem : IComponentFileSystem
    {
        public FakeFileSystem(bool exists)
        {
            Exists = exists;
        }

        public bool Exists { get; }
        public bool ChangeSnapshotDuringRead { get; set; }
        public bool ChangeIdentityOnSecondOpen { get; set; }
        public int OpenCount { get; private set; }
        public int ActiveHandleCount { get; private set; }
        public int ActiveDirectoryHandleCount { get; private set; }
        public bool ReplacementIsBlocked => ActiveHandleCount > 0;

        public string ValidateTrustedRoot(string root) => root.TrimEnd('\\');

        public string ResolveTrustedPath(string trustedRoot, string relativePath) =>
            trustedRoot.TrimEnd('\\') + "\\" + relativePath.Replace('/', '\\');

        public bool FileExists(string absolutePath) => Exists;

        public IComponentFileHandle OpenRead(string trustedRoot, string absolutePath)
        {
            OpenCount++;
            ActiveHandleCount++;
            ActiveDirectoryHandleCount += 2;
            var fileIndex = ChangeIdentityOnSecondOpen && OpenCount > 1 ? (ulong)999 : 456;
            return new FakeFileHandle(
                absolutePath,
                fileIndex,
                ChangeSnapshotDuringRead,
                () =>
                {
                    ActiveHandleCount--;
                    ActiveDirectoryHandleCount -= 2;
                });
        }
    }

    private sealed class FakeFileHandle : IComponentFileHandle
    {
        private readonly string path;
        private readonly ulong fileIndex;
        private readonly bool changeSnapshot;
        private readonly Action onDispose;
        private int snapshots;
        private bool disposed;

        public FakeFileHandle(string path, ulong fileIndex, bool changeSnapshot, Action onDispose)
        {
            this.path = path;
            this.fileIndex = fileIndex;
            this.changeSnapshot = changeSnapshot;
            this.onDispose = onDispose;
            Stream = new MemoryStream(Encoding.UTF8.GetBytes("component"), writable: false);
        }

        public Stream Stream { get; }

        public ComponentHandleSnapshot CaptureSnapshot()
        {
            snapshots++;
            return new ComponentHandleSnapshot(
                path,
                changeSnapshot && snapshots > 1 ? 11 : 10,
                new DateTime(2026, 7, changeSnapshot && snapshots > 1 ? 2 : 1, 0, 0, 0, DateTimeKind.Utc),
                123,
                fileIndex,
                1,
                isReparsePoint: false);
        }

        public void ValidateLease()
        {
            if (disposed)
            {
                throw new ObjectDisposedException(nameof(FakeFileHandle));
            }
        }

        public void Dispose()
        {
            if (!disposed)
            {
                disposed = true;
                Stream.Dispose();
                onDispose();
            }
        }
    }

    private sealed class FakeVersionReader : IComponentVersionReader
    {
        private readonly string version;
        private readonly Func<int>? activeHandleCount;
        private readonly Func<int>? activeDirectoryHandleCount;

        public FakeVersionReader(string version)
            : this(version, null, null)
        {
        }

        public FakeVersionReader(
            string version,
            Func<int>? activeHandleCount,
            Func<int>? activeDirectoryHandleCount)
        {
            this.version = version;
            this.activeHandleCount = activeHandleCount;
            this.activeDirectoryHandleCount = activeDirectoryHandleCount;
        }

        public int ActiveHandlesObserved { get; private set; }
        public int ActiveDirectoryHandlesObserved { get; private set; }

        public string GetFileVersion(IComponentFileHandle handle, string absolutePath)
        {
            ActiveHandlesObserved = activeHandleCount?.Invoke() ?? 1;
            ActiveDirectoryHandlesObserved = activeDirectoryHandleCount?.Invoke() ?? 1;
            handle.ValidateLease();
            Assert.Same(handle.Stream, handle.Stream);
            return version;
        }
    }

    private sealed class FakeArchitectureReader : IComponentArchitectureReader
    {
        private readonly ComponentArchitecture architecture;

        public FakeArchitectureReader(ComponentArchitecture architecture)
        {
            this.architecture = architecture;
        }

        public ComponentArchitecture ReadArchitecture(Stream stream) => architecture;
    }

    private sealed class FakeHashReader : IComponentHashReader
    {
        private readonly string hash;

        public FakeHashReader(string hash)
        {
            this.hash = hash;
        }

        public string ComputeSha256(Stream stream) => hash;
    }
}
