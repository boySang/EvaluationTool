using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Xunit;

namespace AssessmentTool.Windows.Tests.Storage;

public sealed class SqliteProjectRepositoryTests
{
    private const string FixtureSecret = "task5-secret-7e036b85-4183-4dfe-90e6-b61a86ff2ef1";
    private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ImageHash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    [Fact]
    public async Task Vault_secret_never_crosses_repository_boundary_or_reaches_real_sqlite_artifacts()
    {
        using (var database = new TemporaryDatabase())
        using (var walArtifacts = database.OpenWalArtifactSession())
        {
            var vault = new FakeCredentialVault();
            var credentialReference = vault.Store(FixtureSecret);
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();

            var projectId = await repository.CreateProjectAsync("客户A", "项目A", @"C:\Evidence\项目A");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "交换机A", "192.0.2.10", 22, credentialReference);
            await repository.SaveExecutionAsync(CreateSuccessfulRecord(
                projectId, deviceId, "raw.txt", new[] { "page-1.png" }));

            var project = Assert.Single(await repository.GetProjectsAsync());
            var device = Assert.Single(await repository.GetDevicesAsync(projectId));
            var execution = Assert.Single(await repository.GetExecutionsAsync(projectId));
            walArtifacts.Dispose();
            var artifacts = database.GetDatabaseArtifacts();

            Assert.Equal(FixtureSecret, vault.Get(credentialReference));
            Assert.Equal(1, vault.Count);
            Assert.Equal(projectId, project.Id);
            Assert.Equal(credentialReference, device.CredentialReference);
            var persistedDtoStrings = new[]
            {
                project.CustomerName,
                project.ProjectName,
                project.EvidenceRoot,
                device.DisplayName,
                device.Host,
                device.CredentialReference.ToString(),
                execution.ProjectId,
                execution.DeviceId,
                execution.CommandPackVersion,
                execution.CommandId,
                execution.CommandText,
                execution.RawOutputPath!,
                execution.RawOutputSha256!
            }
                .Concat(execution.EvidenceImagePaths)
                .Concat(execution.EvidenceImageSha256s.Keys)
                .Concat(execution.EvidenceImageSha256s.Values);
            Assert.All(persistedDtoStrings, value =>
                Assert.DoesNotContain(FixtureSecret, value, StringComparison.Ordinal));
            var actualDatabasePath = Assert.Single(artifacts, artifactPath =>
                string.Equals(artifactPath, database.Path, StringComparison.OrdinalIgnoreCase));
            Assert.True(new FileInfo(actualDatabasePath).Length > 0);

            Assert.All(artifacts, AssertFixtureSecretAbsent);
            var enumerableTempArtifacts = database.GetEnumerableSqliteTempArtifacts();
            if (!walArtifacts.TempStoreDirectoryConfigured)
            {
                Assert.Empty(enumerableTempArtifacts);
            }

            Assert.All(enumerableTempArtifacts, artifactPath =>
                Assert.True(new FileInfo(artifactPath).Length > 0));
        }
    }

    [Fact]
    public void Repository_add_device_contract_cannot_accept_a_plain_string_secret()
    {
        var methods = typeof(IProjectRepository).GetMethods()
            .Where(method => method.Name == nameof(IProjectRepository.AddDeviceAsync))
            .ToArray();

        Assert.NotEmpty(methods);
        Assert.All(methods, method =>
        {
            var credential = Assert.Single(method.GetParameters(), parameter =>
                string.Equals(parameter.Name, "credentialReference", StringComparison.Ordinal));
            Assert.Equal(typeof(CredentialReference), credential.ParameterType);
        });
    }

    [Fact]
    public async Task Concurrent_repository_instances_initialize_one_schema_version_idempotently()
    {
        using (var database = new TemporaryDatabase())
        {
            var repositories = Enumerable.Range(0, 8)
                .Select(_ => new SqliteProjectRepository(database.ConnectionString))
                .ToArray();

            await Task.WhenAll(repositories.Select(repository => repository.InitializeAsync()));

            var versions = await Task.WhenAll(repositories.Select(repository => repository.GetSchemaVersionAsync()));
            Assert.All(versions, version => Assert.Equal(3, version));
            Assert.Equal(3, database.ReadSchemaVersionRowCount());
            Assert.Equal(0, SqliteProjectRepository.InitializationLockCount);
        }
    }

    [Fact]
    public async Task Device_connection_identity_round_trips_through_schema_migration_two()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户", "项目", @"C:\Evidence");

            await repository.AddDeviceAsync(
                projectId,
                "核心交换机",
                "192.0.2.10",
                22,
                "audit-reader",
                TargetCategory.NetworkDevice,
                ConnectionProtocol.Ssh,
                CredentialReference.New());

            var device = Assert.Single(await repository.GetDevicesAsync(projectId));
            Assert.Equal("audit-reader", device.UserName);
            Assert.Equal(TargetCategory.NetworkDevice, device.Category);
            Assert.Equal(ConnectionProtocol.Ssh, device.Protocol);
            Assert.Equal(3, await repository.GetSchemaVersionAsync());
        }
    }

    [Fact]
    public async Task Existing_device_without_trust_row_reads_as_unconfigured_revision_zero()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户", "项目", @"C:\Evidence");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "Linux服务器", "192.0.2.20", 22, CredentialReference.New());

            var stored = await repository.GetSshHostKeyTrustAsync(deviceId);

            Assert.Equal(deviceId, stored.DeviceId);
            Assert.Equal(0, stored.Revision);
            Assert.Equal(HostKeyTrustState.Unconfigured, stored.Trust.State);
            Assert.Equal(new SshEndpointIdentity("192.0.2.20", 22), stored.Trust.Endpoint);
        }
    }

    [Fact]
    public async Task Ssh_host_key_trust_states_round_trip_with_monotonic_revision()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户", "项目", @"C:\Evidence");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "Linux服务器", "host.example", 2222, CredentialReference.New());
            var endpoint = new SshEndpointIdentity("host.example", 2222);
            var coordinator = HostKeyTrustServices.CreateCoordinator();
            var observedAt = new DateTimeOffset(2026, 7, 17, 1, 2, 3, TimeSpan.Zero);
            var confirmedAt = observedAt.AddMinutes(1);
            var verifiedAt = confirmedAt.AddMinutes(1);
            var mismatchAt = verifiedAt.AddMinutes(1);
            var awaitingConfirmation = coordinator.RecordObservation(
                coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint)),
                "ssh-ed25519",
                "ssh-ed25519 255 SHA256:fixture",
                observedAt);

            var savedAwaiting = await repository.SaveSshHostKeyTrustAsync(
                deviceId, awaitingConfirmation, expectedRevision: 0);
            Assert.Equal(1, savedAwaiting.Revision);
            AssertHostKeyTrust(await repository.GetSshHostKeyTrustAsync(deviceId), 1, awaitingConfirmation);

            var pinned = coordinator.Confirm(awaitingConfirmation, confirmedAt, "测评人员确认");
            var savedPinned = await repository.SaveSshHostKeyTrustAsync(
                deviceId, pinned, savedAwaiting.Revision);
            Assert.Equal(2, savedPinned.Revision);
            AssertHostKeyTrust(await repository.GetSshHostKeyTrustAsync(deviceId), 2, pinned);

            var verified = coordinator.RecordMatchingObservation(pinned, verifiedAt);
            var savedVerified = await repository.SaveSshHostKeyTrustAsync(
                deviceId, verified, savedPinned.Revision);
            Assert.Equal(3, savedVerified.Revision);
            AssertHostKeyTrust(await repository.GetSshHostKeyTrustAsync(deviceId), 3, verified);

            var mismatch = coordinator.RecordMismatchObservation(
                verified,
                "ssh-rsa",
                "ssh-rsa 3072 SHA256:different",
                mismatchAt);
            var savedMismatch = await repository.SaveSshHostKeyTrustAsync(
                deviceId, mismatch, savedVerified.Revision);
            Assert.Equal(4, savedMismatch.Revision);
            AssertHostKeyTrust(await repository.GetSshHostKeyTrustAsync(deviceId), 4, mismatch);

            var replacementAwaiting = coordinator.BeginReconfirmation(mismatch);
            var savedReplacementAwaiting = await repository.SaveSshHostKeyTrustAsync(
                deviceId, replacementAwaiting, savedMismatch.Revision);
            AssertHostKeyTrust(
                await repository.GetSshHostKeyTrustAsync(deviceId),
                5,
                replacementAwaiting);

            var replacementPinned = coordinator.Confirm(
                replacementAwaiting, mismatchAt.AddMinutes(1), "指纹变化人工复核");
            var savedReplacementPinned = await repository.SaveSshHostKeyTrustAsync(
                deviceId, replacementPinned, savedReplacementAwaiting.Revision);
            AssertHostKeyTrust(
                await repository.GetSshHostKeyTrustAsync(deviceId),
                6,
                replacementPinned);

            var replacementVerified = coordinator.RecordMatchingObservation(
                replacementPinned, mismatchAt.AddMinutes(2));
            await repository.SaveSshHostKeyTrustAsync(
                deviceId, replacementVerified, savedReplacementPinned.Revision);
            AssertHostKeyTrust(
                await repository.GetSshHostKeyTrustAsync(deviceId),
                7,
                replacementVerified);
        }
    }

    [Fact]
    public async Task Ssh_host_key_trust_rejects_stale_revision_without_overwriting_current_state()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户", "项目", @"C:\Evidence");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "Linux服务器", "192.0.2.30", 22, CredentialReference.New());
            var endpoint = new SshEndpointIdentity("192.0.2.30", 22);
            var coordinator = HostKeyTrustServices.CreateCoordinator();
            var observedAt = new DateTimeOffset(2026, 7, 17, 2, 0, 0, TimeSpan.Zero);
            var awaiting = coordinator.RecordObservation(
                coordinator.BeginProbe(HostKeyTrust.Unconfigured(endpoint)),
                "ssh-ed25519",
                "ssh-ed25519 255 SHA256:fixture",
                observedAt);
            var firstSave = await repository.SaveSshHostKeyTrustAsync(deviceId, awaiting, 0);
            var pinned = coordinator.Confirm(awaiting, observedAt.AddMinutes(1), "人工确认");
            await repository.SaveSshHostKeyTrustAsync(deviceId, pinned, firstSave.Revision);

            await Assert.ThrowsAsync<PersistenceConcurrencyException>(() =>
                repository.SaveSshHostKeyTrustAsync(deviceId, awaiting, firstSave.Revision));

            var current = await repository.GetSshHostKeyTrustAsync(deviceId);
            Assert.Equal(2, current.Revision);
            Assert.Equal(HostKeyTrustState.Pinned, current.Trust.State);
            Assert.Equal(pinned.Fingerprint, current.Trust.Fingerprint);
        }
    }

    [Fact]
    public async Task Project_evidence_root_preserves_windows_drive_root()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();

            await repository.CreateProjectAsync("客户A", "项目A", @"C:\");

            Assert.Equal(@"C:\", Assert.Single(await repository.GetProjectsAsync()).EvidenceRoot);
        }
    }

    [Theory]
    [InlineData("relative")]
    [InlineData(@"relative\evidence")]
    [InlineData(@"\Evidence")]
    [InlineData("/Evidence")]
    [InlineData("C:relative")]
    public async Task Create_project_rejects_non_rooted_evidence_root_before_full_path_normalization(string evidenceRoot)
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();

            await Assert.ThrowsAsync<ArgumentException>(() =>
                repository.CreateProjectAsync("客户A", "项目A", evidenceRoot));
        }
    }

    [Fact]
    public async Task Create_project_accepts_fully_qualified_drive_and_unc_evidence_roots()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();

            await repository.CreateProjectAsync("客户A", "本地项目", @"C:\Evidence\项目A");
            await repository.CreateProjectAsync("客户B", "UNC项目", @"\\server\share\Evidence\项目B");

            var projects = await repository.GetProjectsAsync();
            Assert.Contains(projects, project => project.EvidenceRoot == @"C:\Evidence\项目A");
            Assert.Contains(projects, project => project.EvidenceRoot == @"\\server\share\Evidence\项目B");
        }
    }

    [Fact]
    public void Built_in_migration_versions_must_be_unique_and_contiguous_from_one()
    {
        MigrationSequence.Validate(new[] { 1, 2, 3 });

        Assert.Throws<InvalidDataException>(() => MigrationSequence.Validate(Array.Empty<int>()));
        Assert.Throws<InvalidDataException>(() => MigrationSequence.Validate(new[] { 2 }));
        Assert.Throws<InvalidDataException>(() => MigrationSequence.Validate(new[] { 1, 1 }));
        Assert.Throws<InvalidDataException>(() => MigrationSequence.Validate(new[] { 1, 3 }));
    }

    private static void AssertHostKeyTrust(
        SshHostKeyTrustRecord actual,
        long expectedRevision,
        HostKeyTrust expected)
    {
        Assert.Equal(expectedRevision, actual.Revision);
        Assert.Equal(expected.State, actual.Trust.State);
        Assert.Equal(expected.Endpoint, actual.Trust.Endpoint);
        Assert.Equal(expected.Algorithm, actual.Trust.Algorithm);
        Assert.Equal(expected.Fingerprint, actual.Trust.Fingerprint);
        Assert.Equal(expected.ObservedAlgorithm, actual.Trust.ObservedAlgorithm);
        Assert.Equal(expected.ObservedFingerprint, actual.Trust.ObservedFingerprint);
        Assert.Equal(expected.ObservedAt, actual.Trust.ObservedAt);
        Assert.Equal(expected.ConfirmedAt, actual.Trust.ConfirmedAt);
        Assert.Equal(expected.ConfirmationSource, actual.Trust.ConfirmationSource);
        Assert.Equal(expected.PreviousAlgorithm, actual.Trust.PreviousAlgorithm);
        Assert.Equal(expected.PreviousFingerprint, actual.Trust.PreviousFingerprint);
        Assert.Equal(expected.PreviousConfirmedAt, actual.Trust.PreviousConfirmedAt);
        Assert.Equal(expected.PreviousConfirmationSource, actual.Trust.PreviousConfirmationSource);
    }

    [Fact]
    public async Task Keyed_async_lock_canceled_waiter_releases_reference_and_final_lease_retires_entry()
    {
        var keyedLock = new KeyedAsyncLock(StringComparer.OrdinalIgnoreCase);
        using (var holder = await keyedLock.AcquireAsync("database", CancellationToken.None))
        using (var cancellation = new CancellationTokenSource())
        {
            var waiting = keyedLock.AcquireAsync("database", cancellation.Token);
            cancellation.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
            Assert.Equal(1, keyedLock.Count);
        }

        Assert.Equal(0, keyedLock.Count);
    }

    [Fact]
    public async Task Keyed_async_lock_survives_high_frequency_acquire_retire_and_recreate()
    {
        var keyedLock = new KeyedAsyncLock(StringComparer.OrdinalIgnoreCase);
        var insideCriticalSection = 0;
        var concurrencyViolation = 0;

        for (var round = 0; round < 100; round++)
        {
            var workers = Enumerable.Range(0, 16).Select(async _ =>
            {
                using (await keyedLock.AcquireAsync("database", CancellationToken.None))
                {
                    if (Interlocked.Increment(ref insideCriticalSection) != 1)
                    {
                        Interlocked.Exchange(ref concurrencyViolation, 1);
                    }

                    await Task.Yield();
                    Interlocked.Decrement(ref insideCriticalSection);
                }
            });

            await Task.WhenAll(workers);
            Assert.Equal(0, keyedLock.Count);
        }

        Assert.Equal(0, concurrencyViolation);
    }

    [Fact]
    public async Task Add_device_rejects_unknown_project_through_foreign_key()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();

            await Assert.ThrowsAnyAsync<Exception>(() => repository.AddDeviceAsync(
                ProjectId.New(), "交换机A", "192.0.2.10", 22, CredentialReference.New()));
        }
    }

    [Fact]
    public async Task Public_database_operation_returns_without_blocking_calling_thread_on_sqlite_lock()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();

            using (var blockingConnection = database.OpenConnection())
            using (var transaction = blockingConnection.BeginTransaction(IsolationLevel.Serializable))
            {
                using (var command = blockingConnection.CreateCommand())
                {
                    command.Transaction = transaction;
                    command.CommandText = "UPDATE schema_version SET applied_at_utc = applied_at_utc WHERE version = @version;";
                    command.Parameters.AddWithValue("@version", 1);
                    command.ExecuteNonQuery();
                }

                var stopwatch = Stopwatch.StartNew();
                var operation = repository.CreateProjectAsync("客户A", "项目A", @"C:\Evidence\项目A");
                stopwatch.Stop();

                Assert.True(stopwatch.Elapsed < TimeSpan.FromMilliseconds(500));
                Assert.False(operation.IsCompleted);
                transaction.Commit();
                await operation;
            }
        }
    }

    [Fact]
    public async Task Failed_execution_write_is_rolled_back_without_partial_evidence_index()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户A", "项目A", @"C:\Evidence\项目A");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "交换机A", "192.0.2.10", 22, CredentialReference.New());
            var record = CreateSuccessfulRecord(projectId, deviceId, "same.txt", new[] { "same.txt" });

            await Assert.ThrowsAnyAsync<Exception>(() => repository.SaveExecutionAsync(record));

            Assert.Empty(await repository.GetExecutionsAsync(projectId));
            Assert.Empty(await repository.GetEvidenceFilesAsync(projectId));
        }
    }

    [Fact]
    public async Task Execution_round_trip_preserves_audit_fields_and_stable_evidence_ordinal()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户A", "项目A", @"C:\Evidence\项目A");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "交换机A", "192.0.2.10", 22, CredentialReference.New());
            var startedAt = new DateTimeOffset(2026, 7, 16, 8, 9, 10, TimeSpan.Zero);
            var record = CreateSuccessfulRecord(
                projectId,
                deviceId,
                "raw/output.txt",
                new[] { "screens/page-2.png", "screens/page-1.png" },
                startedAt);

            await repository.SaveExecutionAsync(record);

            var stored = Assert.Single(await repository.GetExecutionsAsync(projectId));
            var evidence = await repository.GetEvidenceFilesAsync(projectId);

            Assert.Equal(projectId.ToString(), stored.ProjectId);
            Assert.Equal(deviceId.ToString(), stored.DeviceId);
            Assert.Equal(record.ConnectionProtocol, stored.ConnectionProtocol);
            Assert.Equal(record.CommandPackVersion, stored.CommandPackVersion);
            Assert.Equal(record.CommandId, stored.CommandId);
            Assert.Equal(record.CommandText, stored.CommandText);
            Assert.Equal(record.StartedAt, stored.StartedAt);
            Assert.Equal(record.CompletedAt, stored.CompletedAt);
            Assert.Equal(record.Status, stored.Status);
            Assert.Equal(record.ExitCode, stored.ExitCode);
            Assert.Equal(@"raw\output.txt", stored.RawOutputPath);
            Assert.Equal(record.RawOutputSha256, stored.RawOutputSha256);
            Assert.Equal(new[] { @"screens\page-2.png", @"screens\page-1.png" }, stored.EvidenceImagePaths);
            Assert.Collection(
                evidence,
                item => AssertEvidence(item, 0, EvidenceFileKind.RawOutput, @"raw\output.txt"),
                item => AssertEvidence(item, 1, EvidenceFileKind.EvidenceImage, @"screens\page-2.png"),
                item => AssertEvidence(item, 2, EvidenceFileKind.EvidenceImage, @"screens\page-1.png"));
        }
    }

    [Fact]
    public async Task Project_execution_and_evidence_queries_are_isolated_with_nonempty_data()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var firstProjectId = await repository.CreateProjectAsync("客户A", "项目A", @"C:\Evidence\项目A");
            var secondProjectId = await repository.CreateProjectAsync("客户B", "项目B", @"C:\Evidence\项目B");
            var firstDeviceId = await repository.AddDeviceAsync(
                firstProjectId, "交换机A", "192.0.2.10", 22, CredentialReference.New());
            var secondDeviceId = await repository.AddDeviceAsync(
                secondProjectId, "交换机B", "192.0.2.11", 22, CredentialReference.New());
            await repository.SaveExecutionAsync(CreateSuccessfulRecord(
                firstProjectId, firstDeviceId, "first.txt", new[] { "first.png" }, commandId: "command-first"));
            await repository.SaveExecutionAsync(CreateSuccessfulRecord(
                secondProjectId, secondDeviceId, "second.txt", new[] { "second.png" }, commandId: "command-second"));

            var firstExecutions = await repository.GetExecutionsAsync(firstProjectId);
            var secondExecutions = await repository.GetExecutionsAsync(secondProjectId);
            var firstEvidence = await repository.GetEvidenceFilesAsync(firstProjectId);
            var secondEvidence = await repository.GetEvidenceFilesAsync(secondProjectId);

            Assert.Equal("command-first", Assert.Single(firstExecutions).CommandId);
            Assert.Equal("command-second", Assert.Single(secondExecutions).CommandId);
            Assert.All(firstEvidence, item => Assert.Equal(firstProjectId, item.ProjectId));
            Assert.All(secondEvidence, item => Assert.Equal(secondProjectId, item.ProjectId));
            Assert.DoesNotContain(firstEvidence, item => item.RelativePath.StartsWith("second", StringComparison.Ordinal));
            Assert.DoesNotContain(secondEvidence, item => item.RelativePath.StartsWith("first", StringComparison.Ordinal));
        }
    }

    [Theory]
    [InlineData("../raw.txt")]
    [InlineData("..\\raw.txt")]
    [InlineData("C:\\outside.txt")]
    [InlineData("C:drive-relative.txt")]
    [InlineData("/outside.txt")]
    [InlineData("\\\\server\\share\\outside.txt")]
    [InlineData("\\\\?\\C:\\outside.txt")]
    [InlineData("\\\\.\\C:\\outside.txt")]
    [InlineData("file.txt:secret")]
    [InlineData("%2e%2e\\outside.txt")]
    [InlineData("folder\\\\file.txt")]
    [InlineData("folder\\.\\file.txt")]
    [InlineData("folder\\..\\file.txt")]
    [InlineData("folder.\\file.txt")]
    [InlineData("folder \\file.txt")]
    [InlineData("CON")]
    [InlineData("nul.txt")]
    [InlineData("COM1.log")]
    [InlineData("bad?.txt")]
    [InlineData("folder\u001ffile.txt")]
    public async Task Save_execution_rejects_ambiguous_or_unsafe_windows_evidence_path(string invalidPath)
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户A", "项目A", @"C:\Evidence\项目A");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "交换机A", "192.0.2.10", 22, CredentialReference.New());

            await Assert.ThrowsAsync<ArgumentException>(() =>
                repository.SaveExecutionAsync(CreateSuccessfulRecord(projectId, deviceId, invalidPath, new[] { "page-1.png" })));
        }
    }

    [Fact]
    public async Task Save_execution_rejects_nul_in_evidence_path()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户A", "项目A", @"C:\Evidence\项目A");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "交换机A", "192.0.2.10", 22, CredentialReference.New());

            await Assert.ThrowsAsync<ArgumentException>(() =>
                repository.SaveExecutionAsync(CreateSuccessfulRecord(projectId, deviceId, "bad\0name.txt", new[] { "page.png" })));
        }
    }

    [Fact]
    public async Task Composite_foreign_keys_reject_cross_project_execution_and_evidence_rows()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var firstProjectId = await repository.CreateProjectAsync("客户A", "项目A", @"C:\Evidence\项目A");
            var secondProjectId = await repository.CreateProjectAsync("客户B", "项目B", @"C:\Evidence\项目B");
            var firstDeviceId = await repository.AddDeviceAsync(
                firstProjectId, "交换机A", "192.0.2.10", 22, CredentialReference.New());
            var secondDeviceId = await repository.AddDeviceAsync(
                secondProjectId, "交换机B", "192.0.2.11", 22, CredentialReference.New());

            Assert.Throws<SQLiteException>(() => database.InsertExecution(firstProjectId, secondDeviceId));

            await repository.SaveExecutionAsync(CreateSuccessfulRecord(
                firstProjectId, firstDeviceId, "first.txt", new[] { "first.png" }));
            Assert.Throws<SQLiteException>(() => database.InsertMismatchedEvidence(secondProjectId, secondDeviceId));
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public async Task Create_project_rejects_blank_required_input(string customerName)
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();

            await Assert.ThrowsAsync<ArgumentException>(() =>
                repository.CreateProjectAsync(customerName, "项目A", @"C:\Evidence\项目A"));
        }
    }

    private static ExecutionRecord CreateSuccessfulRecord(
        ProjectId projectId,
        DeviceId deviceId,
        string rawOutputPath,
        IEnumerable<string> imagePaths,
        DateTimeOffset? startedAt = null,
        string commandId = "command-1")
    {
        var paths = imagePaths.ToArray();
        var hashes = paths.ToDictionary(path => path, _ => ImageHash, StringComparer.OrdinalIgnoreCase);
        var start = startedAt ?? new DateTimeOffset(2026, 7, 16, 8, 9, 10, TimeSpan.Zero);
        return new ExecutionRecord(
            projectId.ToString(),
            deviceId.ToString(),
            ConnectionProtocol.Ssh,
            "pack-1.2.3",
            commandId,
            "show version",
            start,
            start.AddSeconds(2),
            ExecutionStatus.Succeeded,
            0,
            rawOutputPath,
            Hash,
            paths,
            hashes,
            null);
    }

    private static void AssertEvidence(EvidenceFileRecord item, int ordinal, EvidenceFileKind kind, string path)
    {
        Assert.Equal(ordinal, item.Ordinal);
        Assert.Equal(kind, item.Kind);
        Assert.Equal(path, item.RelativePath);
    }

    private static void AssertFixtureSecretAbsent(string artifactPath)
    {
        var contents = File.ReadAllBytes(artifactPath);
        Assert.False(ContainsSequence(contents, Encoding.UTF8.GetBytes(FixtureSecret)));
        Assert.False(ContainsSequence(contents, Encoding.Unicode.GetBytes(FixtureSecret)));
        Assert.False(ContainsSequence(contents, Encoding.BigEndianUnicode.GetBytes(FixtureSecret)));
    }

    private static bool ContainsSequence(byte[] contents, byte[] target)
    {
        for (var startIndex = 0; startIndex <= contents.Length - target.Length; startIndex++)
        {
            var matches = true;
            for (var offset = 0; offset < target.Length; offset++)
            {
                if (contents[startIndex + offset] != target[offset])
                {
                    matches = false;
                    break;
                }
            }

            if (matches)
            {
                return true;
            }
        }

        return false;
    }

    private sealed class FakeCredentialVault
    {
        private readonly Dictionary<CredentialReference, string> secrets =
            new Dictionary<CredentialReference, string>();

        public int Count => secrets.Count;

        public CredentialReference Store(string secret)
        {
            if (string.IsNullOrEmpty(secret))
            {
                throw new ArgumentException("Secret cannot be empty.", nameof(secret));
            }

            var reference = CredentialReference.New();
            secrets.Add(reference, secret);
            return reference;
        }

        public string Get(CredentialReference reference)
        {
            return secrets[reference];
        }
    }

    private sealed class TemporaryDatabase : IDisposable
    {
        private readonly string directory;

        public TemporaryDatabase()
        {
            directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "AssessmentTool.Task5", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            Path = System.IO.Path.Combine(directory, "assessment.db");
        }

        public string Path { get; }
        public string ConnectionString =>
            "Data Source=" + Path + ";Version=3;Default Timeout=5;Journal Mode=Wal;Pooling=False;";

        public WalArtifactSession OpenWalArtifactSession()
        {
            var connection = OpenConnection();
            try
            {
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "PRAGMA journal_mode = WAL;";
                    Assert.Equal("wal", Convert.ToString(command.ExecuteScalar())!.ToLowerInvariant());
                    command.CommandText = "PRAGMA wal_autocheckpoint = 0;";
                    command.ExecuteNonQuery();
                    command.CommandText = "PRAGMA temp_store = FILE;";
                    command.ExecuteNonQuery();
                }

                var tempStoreDirectoryConfigured = TryConfigureTempStoreDirectory(connection);
                CreateRealTempWorkload(connection);

                return new WalArtifactSession(connection, tempStoreDirectoryConfigured);
            }
            catch
            {
                connection.Dispose();
                throw;
            }
        }

        public SQLiteConnection OpenConnection()
        {
            var connection = new SQLiteConnection(ConnectionString);
            connection.Open();
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;";
                command.ExecuteNonQuery();
            }

            return connection;
        }

        public int ReadSchemaVersionRowCount()
        {
            using (var connection = OpenConnection())
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "SELECT COUNT(*) FROM schema_version;";
                return Convert.ToInt32(command.ExecuteScalar());
            }
        }

        public void InsertExecution(ProjectId projectId, DeviceId deviceId)
        {
            using (var connection = OpenConnection())
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "INSERT INTO executions(id, project_id, device_id, connection_protocol, command_pack_version, command_id, command_text, started_at_utc, completed_at_utc, status) VALUES(@id, @projectId, @deviceId, @protocol, @packVersion, @commandId, @commandText, @startedAtUtc, @completedAtUtc, @status);";
                command.Parameters.AddWithValue("@id", Guid.NewGuid().ToString("D"));
                command.Parameters.AddWithValue("@projectId", projectId.ToString());
                command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                command.Parameters.AddWithValue("@protocol", (int)ConnectionProtocol.Ssh);
                command.Parameters.AddWithValue("@packVersion", "pack-1");
                command.Parameters.AddWithValue("@commandId", "command-mismatch");
                command.Parameters.AddWithValue("@commandText", "show version");
                command.Parameters.AddWithValue("@startedAtUtc", DateTimeOffset.UtcNow.ToString("O"));
                command.Parameters.AddWithValue("@completedAtUtc", DateTimeOffset.UtcNow.ToString("O"));
                command.Parameters.AddWithValue("@status", (int)ExecutionStatus.Failed);
                command.ExecuteNonQuery();
            }
        }

        public void InsertMismatchedEvidence(ProjectId projectId, DeviceId deviceId)
        {
            using (var connection = OpenConnection())
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "INSERT INTO evidence_files(id, execution_id, project_id, device_id, relative_path, sha256, evidence_kind, ordinal, created_at_utc) SELECT @id, id, @projectId, @deviceId, @relativePath, @sha256, @kind, @ordinal, @createdAtUtc FROM executions LIMIT 1;";
                command.Parameters.AddWithValue("@id", Guid.NewGuid().ToString("D"));
                command.Parameters.AddWithValue("@projectId", projectId.ToString());
                command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                command.Parameters.AddWithValue("@relativePath", "mismatch.txt");
                command.Parameters.AddWithValue("@sha256", Hash);
                command.Parameters.AddWithValue("@kind", (int)EvidenceFileKind.RawOutput);
                command.Parameters.AddWithValue("@ordinal", 99);
                command.Parameters.AddWithValue("@createdAtUtc", DateTimeOffset.UtcNow.ToString("O"));
                command.ExecuteNonQuery();
            }
        }

        public IReadOnlyList<string> GetDatabaseArtifacts()
        {
            return Directory.GetFiles(directory, "*", SearchOption.AllDirectories);
        }

        public IReadOnlyList<string> GetEnumerableSqliteTempArtifacts()
        {
            var requiredArtifacts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                Path,
                Path + "-wal",
                Path + "-shm",
                Path + "-journal"
            };
            return GetDatabaseArtifacts()
                .Where(artifactPath => !requiredArtifacts.Contains(artifactPath))
                .ToArray();
        }

        private bool TryConfigureTempStoreDirectory(SQLiteConnection connection)
        {
            using (var command = connection.CreateCommand())
            {
                var escapedDirectory = directory.Replace("'", "''");
                command.CommandText = "PRAGMA temp_store_directory = '" + escapedDirectory + "';";
                try
                {
                    command.ExecuteNonQuery();
                    return true;
                }
                catch (SQLiteException)
                {
                    return false;
                }
            }
        }

        private static void CreateRealTempWorkload(SQLiteConnection connection)
        {
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "CREATE TEMP TABLE temp_scan(sequence INTEGER NOT NULL, payload BLOB NOT NULL);";
                command.ExecuteNonQuery();
                command.CommandText = "INSERT INTO temp_scan(sequence, payload) VALUES(@sequence, randomblob(65536));";
                var sequenceParameter = command.Parameters.Add("@sequence", DbType.Int32);
                for (var sequence = 0; sequence < 128; sequence++)
                {
                    sequenceParameter.Value = sequence;
                    command.ExecuteNonQuery();
                }

                command.Parameters.Clear();
                command.CommandText = "CREATE INDEX temp.temp_index ON temp_scan(sequence DESC);";
                command.ExecuteNonQuery();
                command.CommandText = "SELECT length(payload) FROM temp_scan ORDER BY payload;";
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Assert.Equal(65536, reader.GetInt32(0));
                    }
                }
            }
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(directory, true);
            }
            catch (IOException)
            {
            }
        }

        public sealed class WalArtifactSession : IDisposable
        {
            private SQLiteConnection? connection;
            private readonly bool tempStoreDirectoryConfigured;

            public WalArtifactSession(SQLiteConnection connection, bool tempStoreDirectoryConfigured)
            {
                this.connection = connection;
                this.tempStoreDirectoryConfigured = tempStoreDirectoryConfigured;
            }

            public bool TempStoreDirectoryConfigured => tempStoreDirectoryConfigured;

            public void Dispose()
            {
                var currentConnection = Interlocked.Exchange(ref connection, null);
                if (currentConnection == null)
                {
                    return;
                }

                if (tempStoreDirectoryConfigured)
                {
                    using (var command = currentConnection.CreateCommand())
                    {
                        command.CommandText = "PRAGMA temp_store_directory = '';";
                        command.ExecuteNonQuery();
                    }
                }

                currentConnection.Dispose();
            }
        }
    }
}
