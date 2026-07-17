using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Commands;
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
            Assert.All(versions, version => Assert.Equal(11, version));
            Assert.Equal(11, database.ReadSchemaVersionRowCount());
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
            Assert.Equal(11, await repository.GetSchemaVersionAsync());
        }
    }

    [Fact]
    public async Task Ssh_authentication_and_private_key_reference_round_trip_without_key_material()
    {
        const string privateKeyMaterial = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nprivate-key-secret";
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户", "密钥项目", @"C:\Evidence");
            var vault = new FakeCredentialVault();
            var credentialReference = vault.Store(privateKeyMaterial);
            var privateKeyReference = PrivateKeyReference.Parse(credentialReference.ToString());

            await repository.AddDeviceAsync(
                projectId,
                "密钥服务器",
                "192.0.2.88",
                22,
                "audit-reader",
                TargetCategory.Server,
                ConnectionProtocol.Ssh,
                SshAuthenticationMethod.PrivateKey,
                credentialReference,
                privateKeyReference);

            var device = Assert.Single(await repository.GetDevicesAsync(projectId));
            Assert.Equal(SshAuthenticationMethod.PrivateKey, device.AuthenticationMethod);
            Assert.Equal(credentialReference, device.CredentialReference);
            Assert.Equal(privateKeyReference, device.PrivateKeyReference);
            Assert.Equal(privateKeyMaterial, vault.Get(credentialReference));
            Assert.All(database.GetDatabaseArtifacts(), artifact =>
            {
                var contents = File.ReadAllBytes(artifact);
                Assert.False(ContainsSequence(contents, Encoding.UTF8.GetBytes(privateKeyMaterial)));
                Assert.False(ContainsSequence(contents, Encoding.Unicode.GetBytes(privateKeyMaterial)));
            });
        }
    }

    [Fact]
    public async Task Migration_six_defaults_existing_devices_to_password_authentication()
    {
        using (var database = new TemporaryDatabase())
        {
            var projectId = ProjectId.New();
            var deviceId = DeviceId.New();
            var credentialReference = CredentialReference.New();
            database.CreateVersionFiveDatabase(projectId, deviceId, credentialReference);

            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();

            var device = Assert.Single(await repository.GetDevicesAsync(projectId));
            Assert.Equal(deviceId, device.Id);
            Assert.Equal(SshAuthenticationMethod.Password, device.AuthenticationMethod);
            Assert.Null(device.PrivateKeyReference);
            Assert.Equal(11, await repository.GetSchemaVersionAsync());
        }
    }

    [Fact]
    public async Task Device_identification_history_is_append_only_and_latest_round_trips()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户", "识别项目", @"C:\Evidence");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "Linux服务器", "192.0.2.30", 22, CredentialReference.New());
            var automatic = new DetectionCandidate(
                TargetCategory.Server, "ubuntu", "Linux", null, "22.04", "ID=ubuntu", 0.95);
            var confirmed = new DetectionCandidate(
                TargetCategory.Server, "ubuntu", "Linux", "虚拟机", "22.04", "ID=ubuntu", 0.95);
            var firstAt = new DateTimeOffset(2026, 7, 18, 1, 2, 3, TimeSpan.Zero);

            var first = await repository.AppendDeviceIdentificationAsync(
                deviceId, automatic, false, null, firstAt);
            var second = await repository.AppendDeviceIdentificationAsync(
                deviceId, confirmed, true, "测评人员人工确认", firstAt.AddMinutes(1));

            Assert.Equal(1, first.Revision);
            Assert.Equal(2, second.Revision);
            var latest = await repository.GetLatestDeviceIdentificationAsync(deviceId);
            Assert.NotNull(latest);
            Assert.Equal(2, latest!.Revision);
            Assert.Equal("虚拟机", latest.Model);
            Assert.True(latest.WasUserConfirmed);
            Assert.Equal("测评人员人工确认", latest.ConfirmationSource);
            var history = await repository.GetDeviceIdentificationHistoryAsync(deviceId);
            Assert.Equal(new long[] { 1, 2 }, history.Select(record => record.Revision));

            using (var connection = database.OpenConnection())
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "UPDATE device_identifications SET vendor = 'changed' WHERE device_id = @deviceId;";
                command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                Assert.Throws<SQLiteException>(() => command.ExecuteNonQuery());
                command.Parameters.Clear();
                command.CommandText = "DELETE FROM device_identifications WHERE device_id = @deviceId;";
                command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                Assert.Throws<SQLiteException>(() => command.ExecuteNonQuery());
            }
        }
    }

    [Fact]
    public async Task Concurrent_repository_instances_assign_contiguous_identification_revisions()
    {
        using (var database = new TemporaryDatabase())
        {
            var firstRepository = new SqliteProjectRepository(database.ConnectionString);
            var secondRepository = new SqliteProjectRepository(database.ConnectionString);
            await firstRepository.InitializeAsync();
            var projectId = await firstRepository.CreateProjectAsync("客户", "并发识别项目", @"C:\Evidence");
            var deviceId = await firstRepository.AddDeviceAsync(
                projectId, "Linux服务器", "192.0.2.31", 22, CredentialReference.New());
            var candidate = new DetectionCandidate(
                TargetCategory.Server, "ubuntu", "Linux", null, "24.04", "ID=ubuntu", 0.95);

            var writes = Enumerable.Range(0, 12)
                .Select(index => (index & 1) == 0 ? firstRepository : secondRepository)
                .Select((repository, index) => repository.AppendDeviceIdentificationAsync(
                    deviceId,
                    candidate,
                    false,
                    null,
                    DateTimeOffset.UtcNow.AddSeconds(index)))
                .ToArray();

            await Task.WhenAll(writes);

            var history = await firstRepository.GetDeviceIdentificationHistoryAsync(deviceId);
            Assert.Equal(Enumerable.Range(1, 12).Select(value => (long)value),
                history.Select(record => record.Revision));
            Assert.Equal(0, SqliteProjectRepository.DeviceIdentificationWriteLockCount);
        }
    }

    [Fact]
    public async Task Pending_identification_batches_restore_latest_and_append_resolutions()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户", "候选恢复项目", @"C:\Evidence");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "待识别设备", "192.0.2.32", 22, CredentialReference.New());
            var firstCandidates = new[]
            {
                new DetectionCandidate(
                    TargetCategory.Server, "ubuntu", "Linux", null, "22.04", "ID=ubuntu", 0.70),
                new DetectionCandidate(
                    TargetCategory.Server, "kylin", "Linux", null, "V10", "ID=kylin", 0.65)
            };
            var first = await repository.AppendPendingDeviceIdentificationAsync(
                deviceId, firstCandidates, null, DateTimeOffset.UtcNow);

            var restored = await repository.GetLatestPendingDeviceIdentificationAsync(deviceId);

            Assert.NotNull(restored);
            Assert.Equal(first.BatchId, restored!.BatchId);
            Assert.Equal(new[] { "ubuntu", "kylin" },
                restored.Candidates.Select(candidate => candidate.Vendor));
            var replacement = await repository.AppendPendingDeviceIdentificationAsync(
                deviceId,
                new[]
                {
                    new DetectionCandidate(
                        TargetCategory.Server, "ubuntu", "Linux", null, "24.04", "ID=ubuntu", 0.80)
                },
                first.BatchId,
                DateTimeOffset.UtcNow.AddMinutes(1));
            Assert.Equal(2, replacement.Revision);
            Assert.Equal(replacement.BatchId,
                (await repository.GetLatestPendingDeviceIdentificationAsync(deviceId))!.BatchId);

            await repository.ResolvePendingDeviceIdentificationAsync(
                deviceId,
                replacement.BatchId,
                PendingIdentificationResolution.RevalidatedAndCompleted,
                DateTimeOffset.UtcNow.AddMinutes(2));

            Assert.Null(await repository.GetLatestPendingDeviceIdentificationAsync(deviceId));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                repository.ResolvePendingDeviceIdentificationAsync(
                    deviceId,
                    replacement.BatchId,
                    PendingIdentificationResolution.RevalidatedAndCompleted,
                    DateTimeOffset.UtcNow.AddMinutes(3)));
            using (var connection = database.OpenConnection())
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "UPDATE pending_device_identification_batches SET candidate_count = 1 WHERE batch_id = @batchId;";
                command.Parameters.AddWithValue("@batchId", first.BatchId.ToString("D"));
                Assert.Throws<SQLiteException>(() => command.ExecuteNonQuery());
            }
        }
    }

    [Fact]
    public async Task Completing_pending_identification_is_atomic_and_rejects_a_stale_batch()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync(
                "客户", "识别原子提交项目", @"C:\Evidence");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "Linux服务器", "192.0.2.33", 22, CredentialReference.New());
            var candidate = new DetectionCandidate(
                TargetCategory.Server, "ubuntu", "Linux", null, "24.04", "ID=ubuntu", 0.95);
            var pending = await repository.AppendPendingDeviceIdentificationAsync(
                deviceId, new[] { candidate }, null, DateTimeOffset.UtcNow);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                repository.CompletePendingDeviceIdentificationAsync(
                    deviceId,
                    Guid.NewGuid(),
                    candidate,
                    "测试人工确认",
                    DateTimeOffset.UtcNow.AddMinutes(1)));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                repository.CompletePendingDeviceIdentificationAsync(
                    deviceId,
                    pending.BatchId,
                    new DetectionCandidate(
                        TargetCategory.Server, "kylin", "Linux", null, "V10", "ID=kylin", 0.95),
                    "测试人工确认",
                    DateTimeOffset.UtcNow.AddMinutes(1)));

            Assert.Empty(await repository.GetDeviceIdentificationHistoryAsync(deviceId));
            Assert.Equal(
                pending.BatchId,
                (await repository.GetLatestPendingDeviceIdentificationAsync(deviceId))!.BatchId);

            var completed = await repository.CompletePendingDeviceIdentificationAsync(
                deviceId,
                pending.BatchId,
                candidate,
                "测试人工确认",
                DateTimeOffset.UtcNow.AddMinutes(2));

            Assert.True(completed.WasUserConfirmed);
            Assert.Equal("测试人工确认", completed.ConfirmationSource);
            Assert.Equal(completed.Revision,
                Assert.Single(await repository.GetDeviceIdentificationHistoryAsync(deviceId)).Revision);
            Assert.Null(await repository.GetLatestPendingDeviceIdentificationAsync(deviceId));
        }
    }

    [Fact]
    public async Task Collection_task_ledger_preserves_snapshot_and_marks_abandoned_running_task_interrupted()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户", "任务总账项目", @"C:\Evidence");
            var deviceId = await repository.AddDeviceAsync(
                projectId,
                "Linux服务器",
                "192.0.2.34",
                22,
                "audit-user",
                TargetCategory.Server,
                ConnectionProtocol.Ssh,
                CredentialReference.New());
            var identification = await repository.AppendDeviceIdentificationAsync(
                deviceId,
                new DetectionCandidate(
                    TargetCategory.Server, "ubuntu", "Linux", null, "24.04", "ID=ubuntu", 0.95),
                false,
                null,
                DateTimeOffset.UtcNow);
            var task = new CollectionTaskRecord(
                CollectionTaskId.New(),
                projectId,
                deviceId,
                identification.Revision,
                ConnectionProtocol.Ssh,
                "192.0.2.34",
                22,
                "audit-user",
                SshAuthenticationMethod.Password,
                "ssh-ed25519",
                "ssh-ed25519 255 SHA256:task-ledger-fixture",
                new[]
                {
                    new CollectionTaskCommandSnapshot(
                        0,
                        "generic-linux",
                        "1.0.0",
                        Hash,
                        "generic-linux-hostname",
                        "hostname",
                        "1.1.1",
                        "读取主机名",
                        CommandRiskLevel.Low,
                        false,
                        DateTimeOffset.UtcNow)
                },
                DateTimeOffset.UtcNow);

            await repository.CreateCollectionTaskAsync(task);
            var stored = Assert.Single(await repository.GetCollectionTasksAsync(projectId));
            Assert.Equal(task.Id, stored.Id);
            Assert.Equal(task.Commands[0].CommandPackSha256, Assert.Single(stored.Commands).CommandPackSha256);
            var created = Assert.Single(await repository.GetCollectionTaskEventsAsync(task.Id));
            Assert.Equal(CollectionTaskState.Ready, created.State);

            var running = await repository.AppendCollectionTaskEventAsync(
                task.Id, created.Revision, CollectionTaskState.Running, null, "ExecutionStarted", DateTimeOffset.UtcNow);
            var commandCommitted = await repository.AppendCollectionTaskEventAsync(
                task.Id,
                running.Revision,
                CollectionTaskState.Running,
                0,
                "CommandEvidenceCommitted",
                DateTimeOffset.UtcNow);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                repository.AppendCollectionTaskEventAsync(
                    task.Id, created.Revision, CollectionTaskState.Completed, null, "StaleCompletion", DateTimeOffset.UtcNow));

            Assert.Equal(1, await repository.MarkInterruptedCollectionTasksAsync(DateTimeOffset.UtcNow));
            Assert.Equal(0, await repository.MarkInterruptedCollectionTasksAsync(DateTimeOffset.UtcNow));
            var events = await repository.GetCollectionTaskEventsAsync(task.Id);
            Assert.Equal(
                new[] { CollectionTaskState.Ready, CollectionTaskState.Running, CollectionTaskState.Interrupted },
                events.Where(item => item.State != CollectionTaskState.Running || item.CommandOrdinal == null)
                    .Select(item => item.State));
            Assert.Equal(0, events.Single(item => item.EventCode == "CommandEvidenceCommitted").CommandOrdinal);
            Assert.Equal(commandCommitted.Revision + 1, events.Last().Revision);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                repository.AppendCollectionTaskEventAsync(
                    task.Id,
                    events.Last().Revision,
                    CollectionTaskState.Running,
                    null,
                    "ResumeForbidden",
                    DateTimeOffset.UtcNow));

            using (var connection = database.OpenConnection())
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "UPDATE collection_tasks SET host = 'changed' WHERE id = @id;";
                command.Parameters.AddWithValue("@id", task.Id.ToString());
                Assert.Throws<SQLiteException>(() => command.ExecuteNonQuery());
            }
        }
    }

    [Fact]
    public async Task Device_identification_rejects_unknown_device_and_invalid_confirmation_metadata()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var candidate = new DetectionCandidate(
                TargetCategory.Server, "ubuntu", null, null, "22.04", "ID=ubuntu", 0.95);

            await Assert.ThrowsAnyAsync<Exception>(() => repository.AppendDeviceIdentificationAsync(
                DeviceId.New(), candidate, false, null, DateTimeOffset.UtcNow));
            await Assert.ThrowsAsync<ArgumentException>(() => repository.AppendDeviceIdentificationAsync(
                DeviceId.New(), candidate, true, null, DateTimeOffset.UtcNow));
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
    public async Task Database_confirmation_is_append_only_and_round_trips_audit_evidence()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户", "项目", @"C:\Evidence");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "Linux服务器", "192.0.2.20", 22, CredentialReference.New());
            var confirmedAt = new DateTimeOffset(2026, 7, 17, 6, 9, 0, TimeSpan.Zero);
            var first = CreateDatabaseConfirmation(
                projectId, deviceId, "PostgreSQL", "16.2", 0.92, confirmedAt);
            var second = CreateDatabaseConfirmation(
                projectId, deviceId, "PostgreSQL", "16.3", 0.95, confirmedAt);

            await repository.SaveDatabaseConfirmationAsync(first);
            await repository.SaveDatabaseConfirmationAsync(second);

            var stored = await repository.GetDatabaseConfirmationsAsync(projectId);
            Assert.Equal(2, stored.Count);
            Assert.Equal("16.2", stored[0].Version);
            Assert.Equal("16.3", stored[1].Version);
            Assert.Equal(first.DetectionEvidence, stored[0].DetectionEvidence);
            Assert.Equal(first.ConfirmationSource, stored[0].ConfirmationSource);
            Assert.Equal(first.ConfirmedAt, stored[0].ConfirmedAt);
            Assert.Equal(first.Confidence, stored[0].Confidence);
        }
    }

    [Fact]
    public async Task Database_confirmation_rejects_device_from_another_project()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var firstProject = await repository.CreateProjectAsync("客户", "项目A", @"C:\Evidence\A");
            var secondProject = await repository.CreateProjectAsync("客户", "项目B", @"C:\Evidence\B");
            var deviceId = await repository.AddDeviceAsync(
                firstProject, "Linux服务器", "192.0.2.20", 22, CredentialReference.New());
            var mismatched = CreateDatabaseConfirmation(
                secondProject,
                deviceId,
                "MySQL",
                "8.0",
                0.9,
                new DateTimeOffset(2026, 7, 17, 6, 10, 0, TimeSpan.Zero));

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                repository.SaveDatabaseConfirmationAsync(mismatched));

            Assert.Empty(await repository.GetDatabaseConfirmationsAsync(secondProject));
        }
    }

    [Fact]
    public async Task Command_draft_round_trip_preserves_raw_hash_findings_and_non_executable_state()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var json = "{\"id\":\"draft\",\"name\":\"待审查\",\"version\":\"1.0.0\",\"commands\":[{\"id\":\"unsafe\",\"title\":\"危险样例\",\"targetCategory\":\"Server\",\"commandText\":\"rm -rf /tmp/demo\",\"verificationStatus\":\"Verified\",\"isReadOnly\":true,\"riskLevel\":\"High\"}]}";
            var draft = new CommandDraftImporter().Import(
                Encoding.UTF8.GetBytes(json),
                @"C:\imports\draft.json",
                new DateTimeOffset(2026, 7, 17, 8, 30, 0, TimeSpan.Zero));

            var id = await repository.SaveCommandDraftAsync(draft);
            var stored = Assert.Single(await repository.GetCommandDraftsAsync());

            Assert.Equal(id, stored.Id);
            Assert.Equal("draft.json", stored.SourceFileName);
            Assert.Equal(draft.RawSha256, stored.RawSha256);
            Assert.Equal(json, stored.RawJson);
            Assert.True(stored.IsPendingReview);
            Assert.False(stored.IsExecutable);
            Assert.False(Assert.Single(stored.Commands).IsExecutable);
            Assert.Contains(stored.Findings, finding => finding.Code == "OBVIOUS_MUTATION");
            Assert.Contains(stored.Findings, finding => finding.Code == "DECLARED_VERIFICATION_IGNORED");
        }
    }

    [Fact]
    public async Task Published_command_pack_round_trips_source_hash_and_original_json()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var draftId = await SaveDraftAsync(repository);
            var rawJson = CreateValidPublishedJson("linux-baseline", "Linux 基线", "1.0.0");
            var publishedAt = new DateTimeOffset(2026, 7, 18, 2, 30, 0, TimeSpan.Zero);
            var record = new PublishedCommandPackRecord(
                "linux-baseline",
                "Linux 基线",
                "1.0.0",
                "https://vendor.example/commands/linux-baseline",
                ComputeSha256(rawJson),
                rawJson,
                draftId,
                ComputeSha256(CreateSourceDraftJson()),
                "reviewer-a",
                publishedAt.AddMinutes(-1),
                publishedAt);

            var saved = await repository.PublishCommandPackAsync(record);
            var loaded = await repository.GetPublishedCommandPackAsync("linux-baseline", "1.0.0");
            var all = await repository.GetPublishedCommandPacksAsync();

            AssertPublishedCommandPack(record, saved);
            AssertPublishedCommandPack(record, Assert.IsType<PublishedCommandPackRecord>(loaded));
            AssertPublishedCommandPack(record, Assert.Single(all));
            Assert.Equal(11, await repository.GetSchemaVersionAsync());
        }
    }

    [Fact]
    public async Task Project_command_pack_rollback_appends_revision_and_preserves_history()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户", "锁定项目", @"C:\Evidence\Locks");
            var draftId = await SaveDraftAsync(repository);
            await PublishAsync(repository, draftId, "server-linux", "1.0.0");
            await PublishAsync(repository, draftId, "server-linux", "2.0.0");
            var firstAt = DateTimeOffset.UtcNow;

            var first = await repository.AppendProjectCommandPackLockAsync(
                projectId, "server-linux", "1.0.0", 0, "首次锁定", firstAt);
            var upgrade = await repository.AppendProjectCommandPackLockAsync(
                projectId, "server-linux", "2.0.0", 1, "版本升级", firstAt.AddMinutes(1));
            var rollback = await repository.AppendProjectCommandPackLockAsync(
                projectId, "server-linux", "1.0.0", 2, "回滚到已验证版本", firstAt.AddMinutes(2));

            var current = Assert.IsType<ProjectCommandPackLockRecord>(
                await repository.GetCurrentProjectCommandPackLockAsync(projectId, "server-linux"));
            var currentLocks = await repository.GetCurrentProjectCommandPackLocksAsync(projectId);
            var history = await repository.GetProjectCommandPackLockHistoryAsync(projectId, "server-linux");

            Assert.Equal(1, first.Revision);
            Assert.Null(first.PreviousLockId);
            Assert.Equal(first.Id, upgrade.PreviousLockId);
            Assert.Equal(upgrade.Id, rollback.PreviousLockId);
            Assert.Equal(3, current.Revision);
            Assert.Equal("1.0.0", current.Version);
            Assert.Equal("回滚到已验证版本", current.LockSource);
            Assert.Equal(rollback.Id, Assert.Single(currentLocks).Id);
            Assert.Equal(new[] { "1.0.0", "2.0.0", "1.0.0" }, history.Select(item => item.Version));
            Assert.Equal(new long[] { 1, 2, 3 }, history.Select(item => item.Revision));
        }
    }

    [Fact]
    public async Task Published_packs_and_project_locks_reject_update_and_delete_at_database_level()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync("客户", "不可变项目", @"C:\Evidence\Immutable");
            var draftId = await SaveDraftAsync(repository);
            await PublishAsync(repository, draftId, "immutable-pack", "1.0.0");
            await repository.AppendProjectCommandPackLockAsync(
                projectId, "immutable-pack", "1.0.0", 0, "人工锁定", DateTimeOffset.UtcNow);

            AssertSqliteWriteRejected(database,
                "UPDATE published_command_packs SET raw_json = '{}' WHERE pack_id = 'immutable-pack';");
            AssertSqliteWriteRejected(database,
                "DELETE FROM published_command_packs WHERE pack_id = 'immutable-pack';");
            AssertSqliteWriteRejected(database,
                "UPDATE project_command_pack_locks SET lock_source = 'changed';");
            AssertSqliteWriteRejected(database,
                "DELETE FROM project_command_pack_locks;");
        }
    }

    [Fact]
    public async Task Command_pack_publication_and_locking_enforce_hash_uniqueness_and_foreign_keys()
    {
        using (var database = new TemporaryDatabase())
        {
            var firstRepository = new SqliteProjectRepository(database.ConnectionString);
            var secondRepository = new SqliteProjectRepository(database.ConnectionString);
            await firstRepository.InitializeAsync();
            var projectId = await firstRepository.CreateProjectAsync("客户", "并发项目", @"C:\Evidence\Concurrent");
            var draftId = await SaveDraftAsync(firstRepository);
            var rawJson = CreateValidPublishedJson("concurrent-pack", "并发包", "1.0.0");
            var record = new PublishedCommandPackRecord(
                "concurrent-pack", "并发包", "1.0.0", "https://vendor.example/commands/concurrent-pack",
                ComputeSha256(rawJson), rawJson, draftId, ComputeSha256(CreateSourceDraftJson()),
                "reviewer", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);

            await Assert.ThrowsAsync<InvalidDataException>(() => firstRepository.PublishCommandPackAsync(
                new PublishedCommandPackRecord(
                    "concurrent-pack", "并发包", "1.0.0", "https://vendor.example/commands/concurrent-pack",
                    Hash, rawJson, draftId, ComputeSha256(CreateSourceDraftJson()),
                    "reviewer", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow)));
            var missingDraftJson = CreateValidPublishedJson("missing-draft", "缺少草稿", "1.0.0");
            await Assert.ThrowsAnyAsync<Exception>(() => firstRepository.PublishCommandPackAsync(
                new PublishedCommandPackRecord(
                    "missing-draft", "缺少草稿", "1.0.0", "https://vendor.example/commands/missing-draft",
                    ComputeSha256(missingDraftJson), missingDraftJson, Guid.NewGuid(), ComputeSha256(CreateSourceDraftJson()),
                    "reviewer", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow)));

            var publishAttempts = new[] { firstRepository, secondRepository }
                .Select(async repository =>
                {
                    try
                    {
                        await repository.PublishCommandPackAsync(record);
                        return true;
                    }
                    catch (SQLiteException)
                    {
                        return false;
                    }
                });
            var publishResults = await Task.WhenAll(publishAttempts);
            Assert.Equal(1, publishResults.Count(result => result));
            Assert.Equal(1, publishResults.Count(result => !result));

            await Assert.ThrowsAnyAsync<Exception>(() => firstRepository.AppendProjectCommandPackLockAsync(
                ProjectId.New(), "concurrent-pack", "1.0.0", 0, "未知项目", DateTimeOffset.UtcNow));
            await Assert.ThrowsAnyAsync<Exception>(() => firstRepository.AppendProjectCommandPackLockAsync(
                projectId, "concurrent-pack", "9.9.9", 0, "未知版本", DateTimeOffset.UtcNow));

            var lockAttempts = new[] { firstRepository, secondRepository }
                .Select(async repository =>
                {
                    try
                    {
                        await repository.AppendProjectCommandPackLockAsync(
                            projectId, "concurrent-pack", "1.0.0", 0, "并发锁定", DateTimeOffset.UtcNow);
                        return true;
                    }
                    catch (DBConcurrencyException)
                    {
                        return false;
                    }
                });
            var lockResults = await Task.WhenAll(lockAttempts);
            Assert.Equal(1, lockResults.Count(result => result));
            Assert.Equal(1, lockResults.Count(result => !result));
            Assert.Equal(0, SqliteProjectRepository.PublishedCommandPackWriteLockCount);
            Assert.Equal(0, SqliteProjectRepository.ProjectCommandPackLockWriteLockCount);
        }
    }

    [Fact]
    public async Task Host_software_discovery_round_trips_batches_evidence_and_manual_decisions()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync(
                "客户", "主机软件发现项目", @"C:\Evidence\HostSoftware");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "应用服务器", "192.0.2.61", 22, CredentialReference.New());
            var taskId = await CreateHostSoftwareCollectionTaskAsync(
                repository, projectId, deviceId, "192.0.2.61");
            var firstAt = new DateTimeOffset(2026, 7, 18, 3, 0, 0, TimeSpan.Zero);

            var first = await repository.AppendHostSoftwareDiscoveryBatchAsync(
                projectId,
                deviceId,
                taskId,
                new[]
                {
                    CreateHostSoftwareCandidate(
                        HostSoftwareCategory.Middleware,
                        "Apache Tomcat",
                        "9.0.89",
                        HostSoftwareInstallationType.LocalService,
                        "tomcat9.service",
                        "8080/tcp",
                        HostSoftwareEvidenceKind.Service,
                        "database-host-discovery-linux-services",
                        "tomcat9.service loaded active running",
                        0.92),
                    CreateHostSoftwareCandidate(
                        HostSoftwareCategory.Middleware,
                        "Nginx",
                        "1.24.0",
                        HostSoftwareInstallationType.Container,
                        "reverse-proxy",
                        "0.0.0.0:443->443/tcp",
                        HostSoftwareEvidenceKind.Container,
                        "database-host-discovery-linux-docker-containers",
                        "reverse-proxy nginx:1.24.0 0.0.0.0:443->443/tcp",
                        0.97)
                },
                "collection-task:host-software-001",
                firstAt);

            Assert.Equal(1, first.Revision);
            Assert.Null(first.PreviousBatchId);
            Assert.Equal(2, first.Candidates.Count);
            var restored = await repository.GetLatestHostSoftwareDiscoveryBatchAsync(deviceId);
            Assert.NotNull(restored);
            Assert.Equal(first.BatchId, restored!.BatchId);
            Assert.Equal(taskId, restored.CollectionTaskId);
            Assert.Equal("Apache Tomcat", restored.Candidates[0].Product);
            Assert.Equal(HostSoftwareCategory.Middleware, restored.Candidates[0].Category);
            Assert.Equal(Hash, Assert.Single(restored.Candidates[0].Sources).RawOutputSha256);
            Assert.True(restored.Candidates[0].RequiresUserConfirmation);

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                repository.AppendHostSoftwareCandidateDecisionAsync(
                    restored.Candidates[0].CandidateId,
                    HostSoftwareCandidateDecision.Confirmed,
                    "测评人员A",
                    "时间倒置测试",
                    null,
                    firstAt.AddSeconds(-1)));

            var confirmed = await repository.AppendHostSoftwareCandidateDecisionAsync(
                restored.Candidates[0].CandidateId,
                HostSoftwareCandidateDecision.Confirmed,
                "测评人员A",
                "软件界面人工确认",
                "版本与服务信息一致",
                firstAt.AddMinutes(1));
            var rejected = await repository.AppendHostSoftwareCandidateDecisionAsync(
                restored.Candidates[1].CandidateId,
                HostSoftwareCandidateDecision.Rejected,
                "测评人员A",
                "软件界面人工确认",
                "容器已停止且不属于测评范围",
                firstAt.AddMinutes(2));
            var decisions = await repository.GetHostSoftwareCandidateDecisionsAsync(first.BatchId);

            Assert.Equal(new[] { confirmed.DecisionId, rejected.DecisionId },
                decisions.Select(item => item.DecisionId));
            Assert.Equal(
                new[] { HostSoftwareCandidateDecision.Confirmed, HostSoftwareCandidateDecision.Rejected },
                decisions.Select(item => item.Decision));
            Assert.Equal("版本与服务信息一致", decisions[0].Reason);
        }
    }

    [Fact]
    public async Task Host_software_discovery_appends_revisions_and_never_overwrites_history()
    {
        using (var database = new TemporaryDatabase())
        {
            var repository = new SqliteProjectRepository(database.ConnectionString);
            await repository.InitializeAsync();
            var projectId = await repository.CreateProjectAsync(
                "客户", "追加发现项目", @"C:\Evidence\AppendOnly");
            var deviceId = await repository.AddDeviceAsync(
                projectId, "中间件服务器", "192.0.2.62", 22, CredentialReference.New());
            var taskId = await CreateHostSoftwareCollectionTaskAsync(
                repository, projectId, deviceId, "192.0.2.62");

            var first = await repository.AppendHostSoftwareDiscoveryBatchAsync(
                projectId,
                deviceId,
                taskId,
                new[] { CreateHostSoftwareCandidate() },
                "collection-task:first",
                DateTimeOffset.UtcNow);
            var second = await repository.AppendHostSoftwareDiscoveryBatchAsync(
                projectId,
                deviceId,
                taskId,
                new[]
                {
                    CreateHostSoftwareCandidate(
                        HostSoftwareCategory.Middleware,
                        "Nginx",
                        "1.26.1",
                        HostSoftwareInstallationType.LocalService,
                        "nginx.service",
                        "443/tcp",
                        HostSoftwareEvidenceKind.Process,
                        "database-host-discovery-linux-processes",
                        "nginx: master process /usr/sbin/nginx",
                        0.94)
                },
                "collection-task:second",
                DateTimeOffset.UtcNow.AddMinutes(1));

            var history = await repository.GetHostSoftwareDiscoveryHistoryAsync(deviceId);
            Assert.Equal(new long[] { 1, 2 }, history.Select(batch => batch.Revision));
            Assert.Equal(first.BatchId, second.PreviousBatchId);
            Assert.Equal(new[] { first.BatchId, second.BatchId }, history.Select(batch => batch.BatchId));
            Assert.Equal(second.BatchId,
                (await repository.GetLatestHostSoftwareDiscoveryBatchAsync(deviceId))!.BatchId);

            AssertSqliteWriteRejected(database,
                "UPDATE host_software_discovery_batches SET discovery_source = 'changed';");
            AssertSqliteWriteRejected(database,
                "DELETE FROM host_software_discovery_batches;");
            AssertSqliteWriteRejected(database,
                "UPDATE host_software_discovery_candidates SET product = 'changed';");
            AssertSqliteWriteRejected(database,
                "DELETE FROM host_software_discovery_candidates;");
            AssertSqliteWriteRejected(database,
                "UPDATE host_software_discovery_evidence SET evidence_excerpt = 'changed';");
            AssertSqliteWriteRejected(database,
                "DELETE FROM host_software_discovery_evidence;");
        }
    }

    [Fact]
    public async Task Host_software_decision_is_single_append_only_audit_event()
    {
        using (var database = new TemporaryDatabase())
        {
            var firstRepository = new SqliteProjectRepository(database.ConnectionString);
            var secondRepository = new SqliteProjectRepository(database.ConnectionString);
            await firstRepository.InitializeAsync();
            var projectId = await firstRepository.CreateProjectAsync(
                "客户", "决议项目", @"C:\Evidence\Decisions");
            var deviceId = await firstRepository.AddDeviceAsync(
                projectId, "Web服务器", "192.0.2.63", 22, CredentialReference.New());
            var taskId = await CreateHostSoftwareCollectionTaskAsync(
                firstRepository, projectId, deviceId, "192.0.2.63");
            var batch = await firstRepository.AppendHostSoftwareDiscoveryBatchAsync(
                projectId,
                deviceId,
                taskId,
                new[] { CreateHostSoftwareCandidate() },
                "collection-task:decision",
                DateTimeOffset.UtcNow);
            var candidateId = Assert.Single(batch.Candidates).CandidateId;

            var attempts = new[] { firstRepository, secondRepository }
                .Select(async repository =>
                {
                    try
                    {
                        await repository.AppendHostSoftwareCandidateDecisionAsync(
                            candidateId,
                            HostSoftwareCandidateDecision.Confirmed,
                            "测评人员B",
                            "并发人工确认",
                            null,
                            DateTimeOffset.UtcNow);
                        return true;
                    }
                    catch (InvalidOperationException)
                    {
                        return false;
                    }
                });

            var results = await Task.WhenAll(attempts);
            Assert.Equal(1, results.Count(result => result));
            Assert.Equal(1, results.Count(result => !result));
            Assert.Single(await firstRepository.GetHostSoftwareCandidateDecisionsAsync(batch.BatchId));
            AssertSqliteWriteRejected(database,
                "UPDATE host_software_candidate_decisions SET decision = 2;");
            AssertSqliteWriteRejected(database,
                "DELETE FROM host_software_candidate_decisions;");
            Assert.Equal(0, SqliteProjectRepository.HostSoftwareDecisionWriteLockCount);
        }
    }

    [Fact]
    public async Task Host_software_discovery_rejects_cross_project_device_and_keeps_revisions_contiguous()
    {
        using (var database = new TemporaryDatabase())
        {
            var firstRepository = new SqliteProjectRepository(database.ConnectionString);
            var secondRepository = new SqliteProjectRepository(database.ConnectionString);
            await firstRepository.InitializeAsync();
            var projectId = await firstRepository.CreateProjectAsync(
                "客户", "发现并发项目", @"C:\Evidence\DiscoveryConcurrency");
            var otherProjectId = await firstRepository.CreateProjectAsync(
                "其他客户", "其他项目", @"C:\Evidence\Other");
            var deviceId = await firstRepository.AddDeviceAsync(
                projectId, "并发服务器", "192.0.2.64", 22, CredentialReference.New());
            var taskId = await CreateHostSoftwareCollectionTaskAsync(
                firstRepository, projectId, deviceId, "192.0.2.64");
            var otherDeviceId = await firstRepository.AddDeviceAsync(
                projectId, "其他服务器", "192.0.2.65", 22, CredentialReference.New());
            var otherTaskId = await CreateHostSoftwareCollectionTaskAsync(
                firstRepository, projectId, otherDeviceId, "192.0.2.65");

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                firstRepository.AppendHostSoftwareDiscoveryBatchAsync(
                    otherProjectId,
                    deviceId,
                    taskId,
                    new[] { CreateHostSoftwareCandidate() },
                    "invalid-cross-project",
                    DateTimeOffset.UtcNow));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                firstRepository.AppendHostSoftwareDiscoveryBatchAsync(
                    projectId,
                    deviceId,
                    otherTaskId,
                    new[] { CreateHostSoftwareCandidate() },
                    "invalid-cross-device-task",
                    DateTimeOffset.UtcNow));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                firstRepository.AppendHostSoftwareDiscoveryBatchAsync(
                    projectId,
                    deviceId,
                    CollectionTaskId.New(),
                    new[] { CreateHostSoftwareCandidate() },
                    "invalid-missing-task",
                    DateTimeOffset.UtcNow));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                firstRepository.AppendHostSoftwareDiscoveryBatchAsync(
                    projectId,
                    deviceId,
                    taskId,
                    new[]
                    {
                        CreateHostSoftwareCandidate(
                            sourceCommandId: "command-without-committed-evidence")
                    },
                    "invalid-uncommitted-command",
                    DateTimeOffset.UtcNow));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                firstRepository.AppendHostSoftwareDiscoveryBatchAsync(
                    projectId,
                    deviceId,
                    taskId,
                    new[] { CreateHostSoftwareCandidate() },
                    "invalid-time-order",
                    new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)));

            var writes = Enumerable.Range(0, 8)
                .Select(index => (index & 1) == 0 ? firstRepository : secondRepository)
                .Select((repository, index) => repository.AppendHostSoftwareDiscoveryBatchAsync(
                    projectId,
                    deviceId,
                    taskId,
                    new[] { CreateHostSoftwareCandidate() },
                    "collection-task:concurrent-" + index,
                    DateTimeOffset.UtcNow.AddSeconds(index)))
                .ToArray();
            await Task.WhenAll(writes);

            var history = await firstRepository.GetHostSoftwareDiscoveryHistoryAsync(deviceId);
            Assert.Equal(Enumerable.Range(1, 8).Select(value => (long)value),
                history.Select(batch => batch.Revision));
            Assert.Equal(0, SqliteProjectRepository.HostSoftwareDiscoveryWriteLockCount);
        }
    }

    [Fact]
    public void Built_in_migration_versions_must_be_unique_and_contiguous_from_one()
    {
        MigrationSequence.Validate(Enumerable.Range(1, 11).ToArray());

        Assert.Throws<InvalidDataException>(() => MigrationSequence.Validate(Array.Empty<int>()));
        Assert.Throws<InvalidDataException>(() => MigrationSequence.Validate(new[] { 2 }));
        Assert.Throws<InvalidDataException>(() => MigrationSequence.Validate(new[] { 1, 1 }));
        Assert.Throws<InvalidDataException>(() => MigrationSequence.Validate(new[] { 1, 3 }));
    }

    private static HostSoftwareDiscoveryCandidateInput CreateHostSoftwareCandidate(
        HostSoftwareCategory category = HostSoftwareCategory.Middleware,
        string product = "Apache HTTP Server",
        string? version = "2.4.62",
        HostSoftwareInstallationType installationType = HostSoftwareInstallationType.LocalService,
        string instanceName = "apache2.service",
        string? portEvidence = "80/tcp",
        HostSoftwareEvidenceKind evidenceKind = HostSoftwareEvidenceKind.Service,
        string sourceCommandId = "database-host-discovery-linux-services",
        string excerpt = "apache2.service loaded active running",
        double confidence = 0.93)
    {
        return new HostSoftwareDiscoveryCandidateInput(
            category,
            product,
            version,
            installationType,
            instanceName,
            portEvidence,
            confidence,
            new[]
            {
                new HostSoftwareDiscoveryEvidenceInput(
                    evidenceKind,
                    sourceCommandId,
                    excerpt,
                    Hash)
            });
    }

    private static async Task<CollectionTaskId> CreateHostSoftwareCollectionTaskAsync(
        SqliteProjectRepository repository,
        ProjectId projectId,
        DeviceId deviceId,
        string host)
    {
        var now = DateTimeOffset.UtcNow;
        var identification = await repository.AppendDeviceIdentificationAsync(
            deviceId,
            new DetectionCandidate(
                TargetCategory.Server,
                "ubuntu",
                "Linux",
                null,
                "24.04",
                "ID=ubuntu; VERSION_ID=24.04",
                0.95),
            false,
            null,
            now);
        var task = new CollectionTaskRecord(
            CollectionTaskId.New(),
            projectId,
            deviceId,
            identification.Revision,
            ConnectionProtocol.Ssh,
            host,
            22,
            "未设置",
            SshAuthenticationMethod.Password,
            "ssh-ed25519",
            "ssh-ed25519 255 SHA256:host-software-fixture",
            new[]
            {
                new CollectionTaskCommandSnapshot(
                    0,
                    "database-host-discovery-linux",
                    "1.0.0",
                    Hash,
                    "database-host-discovery-linux-processes",
                    "ps -eo pid,comm",
                    "HOST_DATABASE_DISCOVERY",
                    "读取数据库及中间件进程名",
                    CommandRiskLevel.Low,
                    false,
                    now),
                new CollectionTaskCommandSnapshot(
                    1,
                    "database-host-discovery-linux",
                    "1.0.0",
                    Hash,
                    "database-host-discovery-linux-services",
                    "systemctl list-units --type=service --state=running --no-pager",
                    "HOST_DATABASE_DISCOVERY",
                    "读取数据库及中间件服务名",
                    CommandRiskLevel.Low,
                    false,
                    now),
                new CollectionTaskCommandSnapshot(
                    2,
                    "database-host-discovery-linux",
                    "1.0.0",
                    Hash,
                    "database-host-discovery-linux-docker-containers",
                    "docker ps --no-trunc",
                    "HOST_DATABASE_DISCOVERY",
                    "读取数据库及中间件容器元数据",
                    CommandRiskLevel.Low,
                    true,
                    now)
            },
            now);
        await repository.CreateCollectionTaskAsync(task);
        var running = await repository.AppendCollectionTaskEventAsync(
            task.Id,
            1,
            CollectionTaskState.Running,
            null,
            "ExecutionStarted",
            now);
        var revision = running.Revision;
        for (var ordinal = 0; ordinal < task.Commands.Count; ordinal++)
        {
            var committed = await repository.AppendCollectionTaskEventAsync(
                task.Id,
                revision,
                CollectionTaskState.Running,
                ordinal,
                "CommandEvidenceCommitted",
                now);
            revision = committed.Revision;
        }

        return task.Id;
    }

    private static async Task<Guid> SaveDraftAsync(SqliteProjectRepository repository)
    {
        var json = CreateSourceDraftJson();
        var draft = new CommandDraftImporter().Import(
            Encoding.UTF8.GetBytes(json),
            @"C:\imports\source-draft.json",
            new DateTimeOffset(2026, 7, 18, 2, 0, 0, TimeSpan.Zero));
        return await repository.SaveCommandDraftAsync(draft);
    }

    private static async Task<PublishedCommandPackRecord> PublishAsync(
        SqliteProjectRepository repository,
        Guid draftId,
        string packId,
        string version)
    {
        var rawJson = CreateValidPublishedJson(packId, "测试命令包", version);
        return await repository.PublishCommandPackAsync(new PublishedCommandPackRecord(
            packId,
            "测试命令包",
            version,
            "https://vendor.example/commands/" + packId,
            ComputeSha256(rawJson),
            rawJson,
            draftId,
            ComputeSha256(CreateSourceDraftJson()),
            "storage-test-reviewer",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow));
    }

    private static string ComputeSha256(string value)
    {
        using (var algorithm = SHA256.Create())
        {
            var hash = algorithm.ComputeHash(Encoding.UTF8.GetBytes(value));
            var builder = new StringBuilder(hash.Length * 2);
            foreach (var item in hash)
            {
                builder.Append(item.ToString("x2"));
            }

            return builder.ToString();
        }
    }

    private static string CreateSourceDraftJson()
    {
        return "{\"id\":\"source-draft\",\"name\":\"待审查\",\"version\":\"0.1.0\",\"commands\":[]}";
    }

    private static string CreateValidPublishedJson(string packId, string packName, string version)
    {
        return "{"
            + "\"id\":\"" + packId + "\",\"name\":\"" + packName + "\",\"version\":\"" + version + "\","
            + "\"officialSource\":\"https://vendor.example/commands/" + packId + "\",\"commands\":[{"
            + "\"id\":\"" + packId + "-hostname\",\"title\":\"读取主机名\",\"targetCategory\":\"Server\","
            + "\"commandText\":\"hostname\",\"verificationStatus\":\"Verified\",\"isReadOnly\":true,"
            + "\"vendor\":null,\"productFamily\":null,\"minimumVersion\":\"1.0\",\"maximumVersion\":\"99.0\","
            + "\"checkItem\":\"SYSTEM_IDENTITY\",\"modelRange\":\"*\",\"accountRequirement\":\"只读账户\","
            + "\"riskLevel\":\"Low\",\"timeoutSeconds\":30,\"pagingBehavior\":\"NotApplicable\","
            + "\"resultDescription\":\"主机名\",\"verificationDate\":\"2025-01-01\","
            + "\"officialSource\":\"https://vendor.example/hostname\",\"optional\":false}]}";
    }

    private static void AssertPublishedCommandPack(
        PublishedCommandPackRecord expected,
        PublishedCommandPackRecord actual)
    {
        Assert.Equal(expected.PackId, actual.PackId);
        Assert.Equal(expected.PackName, actual.PackName);
        Assert.Equal(expected.Version, actual.Version);
        Assert.Equal(expected.OfficialSource, actual.OfficialSource);
        Assert.Equal(expected.RawSha256, actual.RawSha256);
        Assert.Equal(expected.RawJson, actual.RawJson);
        Assert.Equal(expected.SourceDraftId, actual.SourceDraftId);
        Assert.Equal(expected.SourceDraftSha256, actual.SourceDraftSha256);
        Assert.Equal(expected.ReviewedBy, actual.ReviewedBy);
        Assert.Equal(expected.ReviewedAt, actual.ReviewedAt);
        Assert.Equal(expected.PublishedAt, actual.PublishedAt);
    }

    private static void AssertSqliteWriteRejected(TemporaryDatabase database, string sql)
    {
        using (var connection = database.OpenConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = sql;
            Assert.Throws<SQLiteException>(() => command.ExecuteNonQuery());
        }
    }

    private static DatabaseConfirmationRecord CreateDatabaseConfirmation(
        ProjectId projectId,
        DeviceId deviceId,
        string product,
        string version,
        double confidence,
        DateTimeOffset confirmedAt)
    {
        return new DatabaseConfirmationRecord(
            projectId,
            deviceId,
            product,
            version,
            DatabaseInstallationType.LocalService,
            "postgresql.service",
            "127.0.0.1:5432",
            "只读进程与服务元数据",
            confidence,
            confirmedAt,
            "测评人员人工确认");
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

        public void CreateVersionFiveDatabase(
            ProjectId projectId,
            DeviceId deviceId,
            CredentialReference credentialReference)
        {
            using (var connection = OpenConnection())
            using (var transaction = connection.BeginTransaction())
            {
                for (var version = 1; version <= 5; version++)
                {
                    var resourceName = version switch
                    {
                        1 => "AssessmentTool.Windows.Storage.Migrations.001_initial.sql",
                        2 => "AssessmentTool.Windows.Storage.Migrations.002_device_connection_identity.sql",
                        3 => "AssessmentTool.Windows.Storage.Migrations.003_ssh_host_key_trust.sql",
                        4 => "AssessmentTool.Windows.Storage.Migrations.004_database_confirmations.sql",
                        5 => "AssessmentTool.Windows.Storage.Migrations.005_command_drafts.sql",
                        _ => throw new InvalidOperationException()
                    };
                    using (var stream = typeof(SqliteProjectRepository).Assembly.GetManifestResourceStream(resourceName))
                    using (var reader = new StreamReader(stream ?? throw new InvalidOperationException(resourceName)))
                    using (var command = connection.CreateCommand())
                    {
                        command.Transaction = transaction;
                        command.CommandText = reader.ReadToEnd();
                        command.ExecuteNonQuery();
                    }
                }

                using (var command = connection.CreateCommand())
                {
                    command.Transaction = transaction;
                    command.CommandText = "CREATE TABLE schema_version (version INTEGER NOT NULL PRIMARY KEY, applied_at_utc TEXT NOT NULL);";
                    command.ExecuteNonQuery();
                    command.CommandText = "INSERT INTO schema_version(version, applied_at_utc) VALUES(1, @time), (2, @time), (3, @time), (4, @time), (5, @time);";
                    command.Parameters.AddWithValue("@time", DateTimeOffset.UtcNow.ToString("O"));
                    command.ExecuteNonQuery();
                    command.Parameters.Clear();
                    command.CommandText = "INSERT INTO projects(id, customer_name, project_name, evidence_root, created_at_utc) VALUES(@projectId, '客户', '旧项目', 'C:\\Evidence', @time);";
                    command.Parameters.AddWithValue("@projectId", projectId.ToString());
                    command.Parameters.AddWithValue("@time", DateTimeOffset.UtcNow.ToString("O"));
                    command.ExecuteNonQuery();
                    command.Parameters.Clear();
                    command.CommandText = "INSERT INTO devices(id, project_id, display_name, host, port, credential_reference, created_at_utc, user_name, target_category, connection_protocol) VALUES(@deviceId, @projectId, '旧设备', '192.0.2.90', 22, @credentialReference, @time, 'audit-reader', 2, 0);";
                    command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                    command.Parameters.AddWithValue("@projectId", projectId.ToString());
                    command.Parameters.AddWithValue("@credentialReference", credentialReference.ToString());
                    command.Parameters.AddWithValue("@time", DateTimeOffset.UtcNow.ToString("O"));
                    command.ExecuteNonQuery();
                }

                transaction.Commit();
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
