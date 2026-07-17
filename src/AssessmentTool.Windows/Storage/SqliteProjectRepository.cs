using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Commands;

namespace AssessmentTool.Windows.Storage;

public sealed class SqliteProjectRepository :
    IProjectRepository,
    ISshHostKeyTrustRepository,
    IDatabaseConfirmationRepository,
    IDeviceIdentificationRepository,
    IPendingDeviceIdentificationRepository,
    ICollectionTaskRepository,
    ICommandDraftRepository
{
    private const int BusyTimeoutMilliseconds = 5000;
    private const string DeviceIdentificationSelect =
        "SELECT device_id, revision, target_category, vendor, product_family, model, version, detection_evidence, confidence, was_user_confirmed, confirmation_source, recorded_at_utc FROM device_identifications";

    private static readonly Migration[] Migrations =
    {
        new Migration(1, "AssessmentTool.Windows.Storage.Migrations.001_initial.sql"),
        new Migration(2, "AssessmentTool.Windows.Storage.Migrations.002_device_connection_identity.sql"),
        new Migration(3, "AssessmentTool.Windows.Storage.Migrations.003_ssh_host_key_trust.sql"),
        new Migration(4, "AssessmentTool.Windows.Storage.Migrations.004_database_confirmations.sql"),
        new Migration(5, "AssessmentTool.Windows.Storage.Migrations.005_command_drafts.sql"),
        new Migration(6, "AssessmentTool.Windows.Storage.Migrations.006_device_ssh_authentication.sql"),
        new Migration(7, "AssessmentTool.Windows.Storage.Migrations.007_device_identifications.sql"),
        new Migration(8, "AssessmentTool.Windows.Storage.Migrations.008_pending_device_identification_batches.sql"),
        new Migration(9, "AssessmentTool.Windows.Storage.Migrations.009_collection_task_ledger.sql")
    };

    private static readonly KeyedAsyncLock InitializationLock =
        new KeyedAsyncLock(StringComparer.OrdinalIgnoreCase);
    private static readonly KeyedAsyncLock DeviceIdentificationWriteLock =
        new KeyedAsyncLock(StringComparer.OrdinalIgnoreCase);
    private static readonly KeyedAsyncLock CollectionTaskWriteLock =
        new KeyedAsyncLock(StringComparer.OrdinalIgnoreCase);

    private readonly string connectionString;
    private readonly string databasePath;

    internal static int InitializationLockCount => InitializationLock.Count;
    internal static int DeviceIdentificationWriteLockCount => DeviceIdentificationWriteLock.Count;

    public SqliteProjectRepository(string connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentException("Connection string cannot be blank.", nameof(connectionString));
        }

        var builder = new SQLiteConnectionStringBuilder(connectionString);
        if (string.IsNullOrWhiteSpace(builder.DataSource) || string.Equals(builder.DataSource, ":memory:", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("A persistent SQLite database path is required.", nameof(connectionString));
        }

        databasePath = Path.GetFullPath(builder.DataSource);
        builder.DataSource = databasePath;
        builder.DefaultTimeout = BusyTimeoutMilliseconds / 1000;
        this.connectionString = builder.ConnectionString;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        MigrationSequence.Validate(Migrations.Select(migration => migration.Version).ToArray());
        using (var lease = await InitializationLock.AcquireAsync(databasePath, cancellationToken).ConfigureAwait(false))
        {
            await RunDatabaseOperationAsync(InitializeCore, cancellationToken).ConfigureAwait(false);
        }
    }

    public Task<ProjectId> CreateProjectAsync(
        string customerName,
        string projectName,
        string evidenceRoot,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync(
            token =>
            {
                var project = new ProjectRecord(
                    ProjectId.New(),
                    customerName,
                    projectName,
                    WindowsEvidenceRootPolicy.Normalize(evidenceRoot, nameof(evidenceRoot)),
                    DateTimeOffset.UtcNow);
                using (var connection = OpenConnection())
                using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                using (var command = connection.CreateCommand())
                {
                    token.ThrowIfCancellationRequested();
                    command.Transaction = transaction;
                    command.CommandText = "INSERT INTO projects(id, customer_name, project_name, evidence_root, created_at_utc) VALUES(@id, @customerName, @projectName, @evidenceRoot, @createdAtUtc);";
                    command.Parameters.AddWithValue("@id", project.Id.ToString());
                    command.Parameters.AddWithValue("@customerName", project.CustomerName);
                    command.Parameters.AddWithValue("@projectName", project.ProjectName);
                    command.Parameters.AddWithValue("@evidenceRoot", project.EvidenceRoot);
                    command.Parameters.AddWithValue("@createdAtUtc", FormatUtc(project.CreatedAt));
                    command.ExecuteNonQuery();
                    token.ThrowIfCancellationRequested();
                    transaction.Commit();
                }

                return project.Id;
            },
            cancellationToken);
    }

    public Task<DeviceId> AddDeviceAsync(
        ProjectId projectId,
        string displayName,
        string host,
        int port,
        CredentialReference credentialReference,
        CancellationToken cancellationToken = default)
    {
        return AddDeviceAsync(
            projectId,
            displayName,
            host,
            port,
            "未设置",
            TargetCategory.Automatic,
            ConnectionProtocol.Ssh,
            SshAuthenticationMethod.Password,
            credentialReference,
            null,
            cancellationToken);
    }

    public Task<DeviceId> AddDeviceAsync(
        ProjectId projectId,
        string displayName,
        string host,
        int port,
        string userName,
        TargetCategory category,
        ConnectionProtocol protocol,
        CredentialReference credentialReference,
        CancellationToken cancellationToken = default)
    {
        return AddDeviceAsync(
            projectId,
            displayName,
            host,
            port,
            userName,
            category,
            protocol,
            SshAuthenticationMethod.Password,
            credentialReference,
            null,
            cancellationToken);
    }

    public Task<DeviceId> AddDeviceAsync(
        ProjectId projectId,
        string displayName,
        string host,
        int port,
        string userName,
        TargetCategory category,
        ConnectionProtocol protocol,
        SshAuthenticationMethod authenticationMethod,
        CredentialReference credentialReference,
        PrivateKeyReference? privateKeyReference,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync(
            token =>
            {
                var device = new DeviceRecord(
                    DeviceId.New(), projectId, displayName, host, port, userName, category, protocol,
                    authenticationMethod, credentialReference, privateKeyReference, DateTimeOffset.UtcNow);
                using (var connection = OpenConnection())
                using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                using (var command = connection.CreateCommand())
                {
                    token.ThrowIfCancellationRequested();
                    command.Transaction = transaction;
                    command.CommandText = "INSERT INTO devices(id, project_id, display_name, host, port, user_name, target_category, connection_protocol, ssh_authentication_method, credential_reference, private_key_reference, created_at_utc) VALUES(@id, @projectId, @displayName, @host, @port, @userName, @targetCategory, @connectionProtocol, @authenticationMethod, @credentialReference, @privateKeyReference, @createdAtUtc);";
                    command.Parameters.AddWithValue("@id", device.Id.ToString());
                    command.Parameters.AddWithValue("@projectId", device.ProjectId.ToString());
                    command.Parameters.AddWithValue("@displayName", device.DisplayName);
                    command.Parameters.AddWithValue("@host", device.Host);
                    command.Parameters.AddWithValue("@port", device.Port);
                    command.Parameters.AddWithValue("@userName", device.UserName);
                    command.Parameters.AddWithValue("@targetCategory", (int)device.Category);
                    command.Parameters.AddWithValue("@connectionProtocol", (int)device.Protocol);
                    command.Parameters.AddWithValue("@authenticationMethod", (int)device.AuthenticationMethod);
                    command.Parameters.AddWithValue("@credentialReference", device.CredentialReference.ToString());
                    command.Parameters.AddWithValue(
                        "@privateKeyReference",
                        device.PrivateKeyReference.HasValue
                            ? (object)device.PrivateKeyReference.Value.ToString()
                            : DBNull.Value);
                    command.Parameters.AddWithValue("@createdAtUtc", FormatUtc(device.CreatedAt));
                    command.ExecuteNonQuery();
                    token.ThrowIfCancellationRequested();
                    transaction.Commit();
                }

                return device.Id;
            },
            cancellationToken);
    }

    public Task SaveExecutionAsync(ExecutionRecord record, CancellationToken cancellationToken = default)
    {
        if (record == null)
        {
            throw new ArgumentNullException(nameof(record));
        }

        return RunDatabaseOperationAsync(
            token =>
            {
                var projectId = ProjectId.Parse(record.ProjectId);
                var deviceId = DeviceId.Parse(record.DeviceId);
                var executionId = Guid.NewGuid().ToString("D");
                using (var connection = OpenConnection())
                using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                {
                    token.ThrowIfCancellationRequested();
                    var evidenceRoot = GetEvidenceRootForDevice(connection, transaction, projectId, deviceId);
                    var normalizedEvidence = NormalizeEvidence(record, evidenceRoot);
                    InsertExecution(connection, transaction, executionId, record, normalizedEvidence.RawOutputPath);
                    InsertEvidenceFiles(
                        connection, transaction, executionId, projectId, deviceId, record, normalizedEvidence);
                    token.ThrowIfCancellationRequested();
                    transaction.Commit();
                }
            },
            cancellationToken);
    }

    public Task<IReadOnlyList<ProjectRecord>> GetProjectsAsync(CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<IReadOnlyList<ProjectRecord>>(
            token =>
            {
                var projects = new List<ProjectRecord>();
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT id, customer_name, project_name, evidence_root, created_at_utc FROM projects ORDER BY created_at_utc, id;";
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            token.ThrowIfCancellationRequested();
                            projects.Add(new ProjectRecord(
                                ProjectId.Parse(reader.GetString(0)),
                                reader.GetString(1),
                                reader.GetString(2),
                                reader.GetString(3),
                                ParseUtc(reader.GetString(4))));
                        }
                    }
                }

                return projects.AsReadOnly();
            },
            cancellationToken);
    }

    public Task<IReadOnlyList<DeviceRecord>> GetDevicesAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<IReadOnlyList<DeviceRecord>>(
            token =>
            {
                var devices = new List<DeviceRecord>();
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT id, project_id, display_name, host, port, user_name, target_category, connection_protocol, ssh_authentication_method, credential_reference, private_key_reference, created_at_utc FROM devices WHERE project_id = @projectId ORDER BY created_at_utc, id;";
                    command.Parameters.AddWithValue("@projectId", projectId.ToString());
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            token.ThrowIfCancellationRequested();
                            devices.Add(new DeviceRecord(
                                DeviceId.Parse(reader.GetString(0)),
                                ProjectId.Parse(reader.GetString(1)),
                                reader.GetString(2),
                                reader.GetString(3),
                                reader.GetInt32(4),
                                reader.GetString(5),
                                ReadEnum<TargetCategory>(reader.GetInt32(6), "target category"),
                                ReadEnum<ConnectionProtocol>(reader.GetInt32(7), "connection protocol"),
                                ReadEnum<SshAuthenticationMethod>(reader.GetInt32(8), "SSH authentication method"),
                                CredentialReference.Parse(reader.GetString(9)),
                                reader.IsDBNull(10)
                                    ? (PrivateKeyReference?)null
                                    : PrivateKeyReference.Parse(reader.GetString(10)),
                                ParseUtc(reader.GetString(11))));
                        }
                    }
                }

                return devices.AsReadOnly();
            },
            cancellationToken);
    }

    public Task<SshHostKeyTrustRecord> GetSshHostKeyTrustAsync(
        DeviceId deviceId,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync(
            token =>
            {
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    token.ThrowIfCancellationRequested();
                    command.CommandText =
                        "SELECT d.host, d.port, t.state, t.algorithm, t.fingerprint, " +
                        "t.observed_algorithm, t.observed_fingerprint, t.observed_at_utc, " +
                        "t.confirmed_at_utc, t.confirmation_source, t.previous_algorithm, " +
                        "t.previous_fingerprint, t.previous_confirmed_at_utc, " +
                        "t.previous_confirmation_source, t.revision " +
                        "FROM devices d LEFT JOIN ssh_host_key_trust t ON t.device_id = d.id " +
                        "WHERE d.id = @deviceId;";
                    command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                    using (var reader = command.ExecuteReader())
                    {
                        if (!reader.Read())
                        {
                            throw new InvalidOperationException("SSH 主机指纹信任对应的设备不存在。");
                        }

                        var endpoint = new SshEndpointIdentity(reader.GetString(0), reader.GetInt32(1));
                        if (reader.IsDBNull(2))
                        {
                            return new SshHostKeyTrustRecord(
                                deviceId,
                                HostKeyTrust.Unconfigured(endpoint),
                                0);
                        }

                        return ReadSshHostKeyTrust(deviceId, endpoint, reader);
                    }
                }
            },
            cancellationToken);
    }

    public Task<SshHostKeyTrustRecord> SaveSshHostKeyTrustAsync(
        DeviceId deviceId,
        HostKeyTrust trust,
        long expectedRevision,
        CancellationToken cancellationToken = default)
    {
        if (trust == null)
        {
            throw new ArgumentNullException(nameof(trust));
        }

        if (expectedRevision < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedRevision), expectedRevision, "Expected revision cannot be negative.");
        }

        EnsurePersistableHostKeyTrustState(trust.State);
        return RunDatabaseOperationAsync(
            token =>
            {
                using (var connection = OpenConnection())
                using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                {
                    token.ThrowIfCancellationRequested();
                    EnsureTrustEndpointMatchesDevice(connection, transaction, deviceId, trust.Endpoint);
                    var nextRevision = checked(expectedRevision + 1);
                    var affectedRows = expectedRevision == 0
                        ? InsertSshHostKeyTrust(connection, transaction, deviceId, trust, nextRevision)
                        : UpdateSshHostKeyTrust(
                            connection, transaction, deviceId, trust, expectedRevision, nextRevision);
                    if (affectedRows != 1)
                    {
                        throw new PersistenceConcurrencyException(
                            "SSH 主机指纹信任已被其他操作修改，请重新读取后再保存。");
                    }

                    token.ThrowIfCancellationRequested();
                    transaction.Commit();
                    return new SshHostKeyTrustRecord(deviceId, trust, nextRevision);
                }
            },
            cancellationToken);
    }

    public Task<IReadOnlyList<ExecutionRecord>> GetExecutionsAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<IReadOnlyList<ExecutionRecord>>(
            token =>
            {
                var storedExecutions = new List<StoredExecution>();
                var executions = new List<ExecutionRecord>();
                using (var connection = OpenConnection())
                {
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT id, project_id, device_id, connection_protocol, command_pack_version, command_id, command_text, started_at_utc, completed_at_utc, status, exit_code, raw_output_path, raw_output_sha256, error_text FROM executions WHERE project_id = @projectId ORDER BY started_at_utc, id;";
                        command.Parameters.AddWithValue("@projectId", projectId.ToString());
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                token.ThrowIfCancellationRequested();
                                storedExecutions.Add(ReadStoredExecution(reader));
                            }
                        }
                    }

                    foreach (var storedExecution in storedExecutions)
                    {
                        token.ThrowIfCancellationRequested();
                        executions.Add(ReadExecution(connection, storedExecution, token));
                    }
                }

                return executions.AsReadOnly();
            },
            cancellationToken);
    }

    public Task<IReadOnlyList<EvidenceFileRecord>> GetEvidenceFilesAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<IReadOnlyList<EvidenceFileRecord>>(
            token =>
            {
                var evidenceFiles = new List<EvidenceFileRecord>();
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT ef.project_id, ef.device_id, ef.relative_path, ef.sha256, ef.evidence_kind, ef.ordinal, ef.created_at_utc FROM evidence_files ef INNER JOIN executions e ON e.id = ef.execution_id WHERE ef.project_id = @projectId ORDER BY e.started_at_utc, e.id, ef.ordinal;";
                    command.Parameters.AddWithValue("@projectId", projectId.ToString());
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            token.ThrowIfCancellationRequested();
                            evidenceFiles.Add(new EvidenceFileRecord(
                                ProjectId.Parse(reader.GetString(0)),
                                DeviceId.Parse(reader.GetString(1)),
                                reader.GetString(2),
                                reader.GetString(3),
                                ReadEnum<EvidenceFileKind>(reader.GetInt32(4), "evidence file kind"),
                                reader.GetInt32(5),
                                ParseUtc(reader.GetString(6))));
                        }
                    }
                }

                return evidenceFiles.AsReadOnly();
            },
            cancellationToken);
    }

    public Task SaveDatabaseConfirmationAsync(
        DatabaseConfirmationRecord record,
        CancellationToken cancellationToken = default)
    {
        if (record == null)
        {
            throw new ArgumentNullException(nameof(record));
        }

        return RunDatabaseOperationAsync(
            token =>
            {
                using (var connection = OpenConnection())
                using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                using (var command = connection.CreateCommand())
                {
                    token.ThrowIfCancellationRequested();
                    GetEvidenceRootForDevice(connection, transaction, record.ProjectId, record.DeviceId);
                    command.Transaction = transaction;
                    command.CommandText = "INSERT INTO database_confirmations(id, project_id, device_id, product, version, installation_type, instance_name, port_evidence, detection_evidence, confidence, confirmed_at_utc, confirmation_source) VALUES(@id, @projectId, @deviceId, @product, @version, @installationType, @instanceName, @portEvidence, @detectionEvidence, @confidence, @confirmedAtUtc, @confirmationSource);";
                    command.Parameters.AddWithValue("@id", Guid.NewGuid().ToString("D"));
                    command.Parameters.AddWithValue("@projectId", record.ProjectId.ToString());
                    command.Parameters.AddWithValue("@deviceId", record.DeviceId.ToString());
                    command.Parameters.AddWithValue("@product", record.Product);
                    command.Parameters.AddWithValue("@version", (object?)record.Version ?? DBNull.Value);
                    command.Parameters.AddWithValue("@installationType", (int)record.InstallationType);
                    command.Parameters.AddWithValue("@instanceName", record.InstanceName);
                    command.Parameters.AddWithValue("@portEvidence", (object?)record.PortEvidence ?? DBNull.Value);
                    command.Parameters.AddWithValue("@detectionEvidence", record.DetectionEvidence);
                    command.Parameters.AddWithValue("@confidence", record.Confidence);
                    command.Parameters.AddWithValue("@confirmedAtUtc", FormatUtc(record.ConfirmedAt));
                    command.Parameters.AddWithValue("@confirmationSource", record.ConfirmationSource);
                    command.ExecuteNonQuery();
                    token.ThrowIfCancellationRequested();
                    transaction.Commit();
                }
            },
            cancellationToken);
    }

    public Task<IReadOnlyList<DatabaseConfirmationRecord>> GetDatabaseConfirmationsAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<IReadOnlyList<DatabaseConfirmationRecord>>(
            token =>
            {
                var records = new List<DatabaseConfirmationRecord>();
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT project_id, device_id, product, version, installation_type, instance_name, port_evidence, detection_evidence, confidence, confirmed_at_utc, confirmation_source FROM database_confirmations WHERE project_id = @projectId ORDER BY confirmed_at_utc, rowid;";
                    command.Parameters.AddWithValue("@projectId", projectId.ToString());
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            token.ThrowIfCancellationRequested();
                            records.Add(new DatabaseConfirmationRecord(
                                ProjectId.Parse(reader.GetString(0)),
                                DeviceId.Parse(reader.GetString(1)),
                                reader.GetString(2),
                                ReadNullableString(reader, 3),
                                ReadEnum<DatabaseInstallationType>(reader.GetInt32(4), "database installation type"),
                                reader.GetString(5),
                                ReadNullableString(reader, 6),
                                reader.GetString(7),
                                reader.GetDouble(8),
                                ParseUtc(reader.GetString(9)),
                                reader.GetString(10)));
                        }
                    }
                }

                return records.AsReadOnly();
            },
            cancellationToken);
    }

    public async Task<DeviceIdentificationRecord> AppendDeviceIdentificationAsync(
        DeviceId deviceId,
        DetectionCandidate candidate,
        bool wasUserConfirmed,
        string? confirmationSource,
        DateTimeOffset recordedAt,
        CancellationToken cancellationToken = default)
    {
        if (candidate == null)
        {
            throw new ArgumentNullException(nameof(candidate));
        }

        var lockKey = databasePath + "\0" + deviceId;
        using (var lease = await DeviceIdentificationWriteLock
            .AcquireAsync(lockKey, cancellationToken)
            .ConfigureAwait(false))
        {
            return await RunDatabaseOperationAsync(
                token =>
                {
                    using (var connection = OpenConnection())
                    using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                    {
                        token.ThrowIfCancellationRequested();
                        long revision;
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "SELECT COALESCE(MAX(revision), 0) FROM device_identifications WHERE device_id = @deviceId;";
                            command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                            revision = checked(Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) + 1L);
                        }

                        var record = new DeviceIdentificationRecord(
                            deviceId,
                            revision,
                            candidate.Category,
                            candidate.Vendor,
                            candidate.ProductFamily,
                            candidate.Model,
                            candidate.Version,
                            candidate.Evidence,
                            candidate.Confidence,
                            wasUserConfirmed,
                            confirmationSource,
                            recordedAt);
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "INSERT INTO device_identifications(device_id, revision, target_category, vendor, product_family, model, version, detection_evidence, confidence, was_user_confirmed, confirmation_source, recorded_at_utc) VALUES(@deviceId, @revision, @targetCategory, @vendor, @productFamily, @model, @version, @evidence, @confidence, @wasUserConfirmed, @confirmationSource, @recordedAtUtc);";
                            AddDeviceIdentificationParameters(command, record);
                            command.ExecuteNonQuery();
                        }

                        token.ThrowIfCancellationRequested();
                        transaction.Commit();
                        return record;
                    }
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public Task<DeviceIdentificationRecord?> GetLatestDeviceIdentificationAsync(
        DeviceId deviceId,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<DeviceIdentificationRecord?>(
            token =>
            {
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    token.ThrowIfCancellationRequested();
                    command.CommandText = DeviceIdentificationSelect
                        + " WHERE device_id = @deviceId ORDER BY revision DESC LIMIT 1;";
                    command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                    using (var reader = command.ExecuteReader())
                    {
                        return reader.Read() ? ReadDeviceIdentification(reader) : null;
                    }
                }
            },
            cancellationToken);
    }

    public Task<IReadOnlyList<DeviceIdentificationRecord>> GetDeviceIdentificationHistoryAsync(
        DeviceId deviceId,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<IReadOnlyList<DeviceIdentificationRecord>>(
            token =>
            {
                var records = new List<DeviceIdentificationRecord>();
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = DeviceIdentificationSelect
                        + " WHERE device_id = @deviceId ORDER BY revision;";
                    command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            token.ThrowIfCancellationRequested();
                            records.Add(ReadDeviceIdentification(reader));
                        }
                    }
                }

                return records.AsReadOnly();
            },
            cancellationToken);
    }

    public async Task<PendingDeviceIdentificationBatch> AppendPendingDeviceIdentificationAsync(
        DeviceId deviceId,
        IReadOnlyList<DetectionCandidate> candidates,
        Guid? supersededBatchId,
        DateTimeOffset recordedAt,
        CancellationToken cancellationToken = default)
    {
        if (candidates == null)
        {
            throw new ArgumentNullException(nameof(candidates));
        }

        if (supersededBatchId == Guid.Empty)
        {
            throw new ArgumentException("被替换的识别候选批次标识不能为空。", nameof(supersededBatchId));
        }

        var copiedCandidates = candidates.ToArray();
        foreach (var candidate in copiedCandidates)
        {
            if (candidate == null)
            {
                throw new ArgumentException("识别候选批次不能包含空项。", nameof(candidates));
            }

            _ = new DeviceIdentificationRecord(
                deviceId, 1, candidate.Category, candidate.Vendor, candidate.ProductFamily,
                candidate.Model, candidate.Version, candidate.Evidence, candidate.Confidence,
                false, null, recordedAt);
        }

        var batchId = Guid.NewGuid();
        var lockKey = databasePath + "\0" + deviceId;
        using (var lease = await DeviceIdentificationWriteLock
            .AcquireAsync(lockKey, cancellationToken)
            .ConfigureAwait(false))
        {
            return await RunDatabaseOperationAsync(
                token =>
                {
                    using (var connection = OpenConnection())
                    using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                    {
                        token.ThrowIfCancellationRequested();
                        long revision;
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "SELECT COALESCE(MAX(revision), 0) FROM pending_device_identification_batches WHERE device_id = @deviceId;";
                            command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                            revision = checked(Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) + 1L);
                        }

                        var batch = new PendingDeviceIdentificationBatch(
                            batchId, deviceId, revision, copiedCandidates, recordedAt);
                        if (supersededBatchId.HasValue)
                        {
                            InsertPendingIdentificationResolution(
                                connection,
                                transaction,
                                deviceId,
                                supersededBatchId.Value,
                                PendingIdentificationResolution.SupersededByNewDetection,
                                recordedAt);
                        }

                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "INSERT INTO pending_device_identification_batches(batch_id, device_id, revision, candidate_count, recorded_at_utc) VALUES(@batchId, @deviceId, @revision, @candidateCount, @recordedAtUtc);";
                            command.Parameters.AddWithValue("@batchId", batch.BatchId.ToString("D"));
                            command.Parameters.AddWithValue("@deviceId", batch.DeviceId.ToString());
                            command.Parameters.AddWithValue("@revision", batch.Revision);
                            command.Parameters.AddWithValue("@candidateCount", batch.Candidates.Count);
                            command.Parameters.AddWithValue("@recordedAtUtc", FormatUtc(batch.RecordedAt));
                            command.ExecuteNonQuery();
                        }

                        for (var ordinal = 0; ordinal < batch.Candidates.Count; ordinal++)
                        {
                            InsertPendingIdentificationCandidate(
                                connection, transaction, batch.BatchId, ordinal, batch.Candidates[ordinal]);
                        }

                        token.ThrowIfCancellationRequested();
                        transaction.Commit();
                        return batch;
                    }
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public Task<PendingDeviceIdentificationBatch?> GetLatestPendingDeviceIdentificationAsync(
        DeviceId deviceId,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<PendingDeviceIdentificationBatch?>(
            token =>
            {
                using (var connection = OpenConnection())
                {
                    Guid batchId;
                    long revision;
                    int candidateCount;
                    DateTimeOffset recordedAt;
                    bool isResolved;
                    using (var command = connection.CreateCommand())
                    {
                        token.ThrowIfCancellationRequested();
                        command.CommandText = "SELECT b.batch_id, b.revision, b.candidate_count, b.recorded_at_utc, CASE WHEN r.batch_id IS NULL THEN 0 ELSE 1 END FROM pending_device_identification_batches b LEFT JOIN pending_device_identification_resolutions r ON r.batch_id = b.batch_id WHERE b.device_id = @deviceId ORDER BY b.revision DESC LIMIT 1;";
                        command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                        using (var reader = command.ExecuteReader())
                        {
                            if (!reader.Read())
                            {
                                return null;
                            }

                            batchId = Guid.Parse(reader.GetString(0));
                            revision = reader.GetInt64(1);
                            candidateCount = reader.GetInt32(2);
                            recordedAt = ParseUtc(reader.GetString(3));
                            isResolved = reader.GetInt32(4) == 1;
                        }
                    }

                    if (isResolved)
                    {
                        return null;
                    }

                    var candidates = new List<DetectionCandidate>();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT target_category, vendor, product_family, model, version, detection_evidence, confidence FROM pending_device_identification_candidates WHERE batch_id = @batchId ORDER BY ordinal;";
                        command.Parameters.AddWithValue("@batchId", batchId.ToString("D"));
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                token.ThrowIfCancellationRequested();
                                candidates.Add(new DetectionCandidate(
                                    ReadEnum<TargetCategory>(reader.GetInt32(0), "pending identification target category"),
                                    ReadNullableString(reader, 1),
                                    ReadNullableString(reader, 2),
                                    ReadNullableString(reader, 3),
                                    ReadNullableString(reader, 4),
                                    reader.GetString(5),
                                    reader.GetDouble(6)));
                            }
                        }
                    }

                    if (candidates.Count != candidateCount)
                    {
                        throw new InvalidDataException("待确认识别候选批次不完整，已阻止恢复。");
                    }

                    return new PendingDeviceIdentificationBatch(
                        batchId, deviceId, revision, candidates, recordedAt);
                }
            },
            cancellationToken);
    }

    public async Task ResolvePendingDeviceIdentificationAsync(
        DeviceId deviceId,
        Guid batchId,
        PendingIdentificationResolution resolution,
        DateTimeOffset resolvedAt,
        CancellationToken cancellationToken = default)
    {
        if (!Enum.IsDefined(typeof(PendingIdentificationResolution), resolution))
        {
            throw new ArgumentOutOfRangeException(nameof(resolution), resolution, "待确认识别批次处理结果无效。");
        }

        if (batchId == Guid.Empty)
        {
            throw new ArgumentException("待确认识别批次标识不能为空。", nameof(batchId));
        }

        if (resolvedAt == default(DateTimeOffset))
        {
            throw new ArgumentException("待确认识别批次处理时间不能为空。", nameof(resolvedAt));
        }

        var lockKey = databasePath + "\0" + deviceId;
        using (var lease = await DeviceIdentificationWriteLock
            .AcquireAsync(lockKey, cancellationToken)
            .ConfigureAwait(false))
        {
            await RunDatabaseOperationAsync(
                token =>
                {
                    using (var connection = OpenConnection())
                    using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                    {
                        token.ThrowIfCancellationRequested();
                        InsertPendingIdentificationResolution(
                            connection, transaction, deviceId, batchId, resolution, resolvedAt);
                        transaction.Commit();
                    }
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<DeviceIdentificationRecord> CompletePendingDeviceIdentificationAsync(
        DeviceId deviceId,
        Guid batchId,
        DetectionCandidate confirmedCandidate,
        string confirmationSource,
        DateTimeOffset recordedAt,
        CancellationToken cancellationToken = default)
    {
        if (batchId == Guid.Empty)
        {
            throw new ArgumentException("待确认识别批次标识不能为空。", nameof(batchId));
        }

        if (confirmedCandidate == null)
        {
            throw new ArgumentNullException(nameof(confirmedCandidate));
        }

        var lockKey = databasePath + "\0" + deviceId;
        using (var lease = await DeviceIdentificationWriteLock
            .AcquireAsync(lockKey, cancellationToken)
            .ConfigureAwait(false))
        {
            return await RunDatabaseOperationAsync(
                token =>
                {
                    using (var connection = OpenConnection())
                    using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                    {
                        token.ThrowIfCancellationRequested();
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "SELECT COUNT(*) FROM pending_device_identification_candidates c INNER JOIN pending_device_identification_batches b ON b.batch_id = c.batch_id LEFT JOIN pending_device_identification_resolutions r ON r.batch_id = b.batch_id WHERE b.batch_id = @batchId AND b.device_id = @deviceId AND r.batch_id IS NULL AND c.target_category = @targetCategory AND c.vendor IS @vendor AND c.product_family IS @productFamily AND c.model IS @model AND c.version IS @version AND c.detection_evidence = @evidence AND c.confidence = @confidence;";
                            command.Parameters.AddWithValue("@batchId", batchId.ToString("D"));
                            command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                            command.Parameters.AddWithValue("@targetCategory", (int)confirmedCandidate.Category);
                            command.Parameters.AddWithValue("@vendor", (object?)confirmedCandidate.Vendor ?? DBNull.Value);
                            command.Parameters.AddWithValue("@productFamily", (object?)confirmedCandidate.ProductFamily ?? DBNull.Value);
                            command.Parameters.AddWithValue("@model", (object?)confirmedCandidate.Model ?? DBNull.Value);
                            command.Parameters.AddWithValue("@version", (object?)confirmedCandidate.Version ?? DBNull.Value);
                            command.Parameters.AddWithValue("@evidence", confirmedCandidate.Evidence);
                            command.Parameters.AddWithValue("@confidence", confirmedCandidate.Confidence);
                            if (Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) != 1L)
                            {
                                throw new InvalidOperationException("当前识别结果与待确认候选批次不一致，已阻止提交。");
                            }
                        }

                        long revision;
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "SELECT COALESCE(MAX(revision), 0) FROM device_identifications WHERE device_id = @deviceId;";
                            command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                            revision = checked(Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) + 1L);
                        }

                        var record = new DeviceIdentificationRecord(
                            deviceId,
                            revision,
                            confirmedCandidate.Category,
                            confirmedCandidate.Vendor,
                            confirmedCandidate.ProductFamily,
                            confirmedCandidate.Model,
                            confirmedCandidate.Version,
                            confirmedCandidate.Evidence,
                            confirmedCandidate.Confidence,
                            true,
                            confirmationSource,
                            recordedAt);
                        InsertPendingIdentificationResolution(
                            connection,
                            transaction,
                            deviceId,
                            batchId,
                            PendingIdentificationResolution.RevalidatedAndCompleted,
                            recordedAt);
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "INSERT INTO device_identifications(device_id, revision, target_category, vendor, product_family, model, version, detection_evidence, confidence, was_user_confirmed, confirmation_source, recorded_at_utc) VALUES(@deviceId, @revision, @targetCategory, @vendor, @productFamily, @model, @version, @evidence, @confidence, @wasUserConfirmed, @confirmationSource, @recordedAtUtc);";
                            AddDeviceIdentificationParameters(command, record);
                            command.ExecuteNonQuery();
                        }

                        token.ThrowIfCancellationRequested();
                        transaction.Commit();
                        return record;
                    }
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<CollectionTaskRecord> CreateCollectionTaskAsync(
        CollectionTaskRecord task,
        CancellationToken cancellationToken = default)
    {
        if (task == null)
        {
            throw new ArgumentNullException(nameof(task));
        }

        using (var lease = await CollectionTaskWriteLock
            .AcquireAsync(databasePath, cancellationToken)
            .ConfigureAwait(false))
        {
            return await RunDatabaseOperationAsync(
                token =>
                {
                    using (var connection = OpenConnection())
                    using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                    {
                        token.ThrowIfCancellationRequested();
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "INSERT INTO collection_tasks(id, project_id, device_id, identification_revision, connection_protocol, host, port, user_name, authentication_method, host_key_algorithm, host_key_fingerprint, command_count, created_at_utc) VALUES(@id, @projectId, @deviceId, @identificationRevision, @protocol, @host, @port, @userName, @authenticationMethod, @hostKeyAlgorithm, @hostKeyFingerprint, @commandCount, @createdAtUtc);";
                            command.Parameters.AddWithValue("@id", task.Id.ToString());
                            command.Parameters.AddWithValue("@projectId", task.ProjectId.ToString());
                            command.Parameters.AddWithValue("@deviceId", task.DeviceId.ToString());
                            command.Parameters.AddWithValue("@identificationRevision", task.IdentificationRevision);
                            command.Parameters.AddWithValue("@protocol", (int)task.ConnectionProtocol);
                            command.Parameters.AddWithValue("@host", task.Host);
                            command.Parameters.AddWithValue("@port", task.Port);
                            command.Parameters.AddWithValue("@userName", task.UserName);
                            command.Parameters.AddWithValue("@authenticationMethod", (int)task.AuthenticationMethod);
                            command.Parameters.AddWithValue("@hostKeyAlgorithm", task.HostKeyAlgorithm);
                            command.Parameters.AddWithValue("@hostKeyFingerprint", task.HostKeyFingerprint);
                            command.Parameters.AddWithValue("@commandCount", task.Commands.Count);
                            command.Parameters.AddWithValue("@createdAtUtc", FormatUtc(task.CreatedAt));
                            command.ExecuteNonQuery();
                        }

                        foreach (var item in task.Commands)
                        {
                            token.ThrowIfCancellationRequested();
                            using (var command = connection.CreateCommand())
                            {
                                command.Transaction = transaction;
                                command.CommandText = "INSERT INTO collection_task_commands(task_id, ordinal, command_pack_id, command_pack_version, command_pack_sha256, command_id, command_text, check_item, result_description, risk_level, is_optional, safety_validated_at_utc) VALUES(@taskId, @ordinal, @packId, @packVersion, @packSha256, @commandId, @commandText, @checkItem, @resultDescription, @riskLevel, @isOptional, @safetyValidatedAtUtc);";
                                command.Parameters.AddWithValue("@taskId", task.Id.ToString());
                                command.Parameters.AddWithValue("@ordinal", item.Ordinal);
                                command.Parameters.AddWithValue("@packId", item.CommandPackId);
                                command.Parameters.AddWithValue("@packVersion", item.CommandPackVersion);
                                command.Parameters.AddWithValue("@packSha256", item.CommandPackSha256);
                                command.Parameters.AddWithValue("@commandId", item.CommandId);
                                command.Parameters.AddWithValue("@commandText", item.CommandText);
                                command.Parameters.AddWithValue("@checkItem", item.CheckItem);
                                command.Parameters.AddWithValue("@resultDescription", item.ResultDescription);
                                command.Parameters.AddWithValue("@riskLevel", (int)item.RiskLevel);
                                command.Parameters.AddWithValue("@isOptional", item.IsOptional ? 1 : 0);
                                command.Parameters.AddWithValue("@safetyValidatedAtUtc", FormatUtc(item.SafetyValidatedAt));
                                command.ExecuteNonQuery();
                            }
                        }

                        InsertCollectionTaskEvent(
                            connection,
                            transaction,
                            new CollectionTaskEventRecord(
                                task.Id, 1, CollectionTaskState.Ready, null, "TaskCreated", task.CreatedAt));
                        transaction.Commit();
                        return task;
                    }
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<CollectionTaskEventRecord> AppendCollectionTaskEventAsync(
        CollectionTaskId taskId,
        long expectedRevision,
        CollectionTaskState state,
        int? commandOrdinal,
        string eventCode,
        DateTimeOffset occurredAt,
        CancellationToken cancellationToken = default)
    {
        if (expectedRevision < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedRevision));
        }

        using (var lease = await CollectionTaskWriteLock
            .AcquireAsync(databasePath, cancellationToken)
            .ConfigureAwait(false))
        {
            return await RunDatabaseOperationAsync(
                token =>
                {
                    using (var connection = OpenConnection())
                    using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                    {
                        token.ThrowIfCancellationRequested();
                        long currentRevision;
                        CollectionTaskState currentState;
                        int commandCount;
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "SELECT e.revision, e.state, t.command_count FROM collection_tasks t INNER JOIN collection_task_events e ON e.task_id = t.id WHERE t.id = @taskId ORDER BY e.revision DESC LIMIT 1;";
                            command.Parameters.AddWithValue("@taskId", taskId.ToString());
                            using (var reader = command.ExecuteReader())
                            {
                                if (!reader.Read())
                                {
                                    throw new InvalidOperationException("采集任务不存在。");
                                }

                                currentRevision = reader.GetInt64(0);
                                currentState = ReadEnum<CollectionTaskState>(reader.GetInt32(1), "collection task state");
                                commandCount = reader.GetInt32(2);
                            }
                        }

                        if (currentRevision != expectedRevision)
                        {
                            throw new InvalidOperationException("采集任务状态已变化，请刷新后重试。");
                        }

                        if (!CanTransitionCollectionTask(currentState, state))
                        {
                            throw new InvalidOperationException("采集任务状态转换不允许。");
                        }

                        if (commandOrdinal.HasValue && commandOrdinal.Value >= commandCount)
                        {
                            throw new ArgumentOutOfRangeException(nameof(commandOrdinal));
                        }

                        var record = new CollectionTaskEventRecord(
                            taskId,
                            checked(currentRevision + 1L),
                            state,
                            commandOrdinal,
                            eventCode,
                            occurredAt);
                        InsertCollectionTaskEvent(connection, transaction, record);
                        transaction.Commit();
                        return record;
                    }
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public Task<IReadOnlyList<CollectionTaskRecord>> GetCollectionTasksAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<IReadOnlyList<CollectionTaskRecord>>(
            token =>
            {
                var headers = new List<StoredCollectionTaskHeader>();
                using (var connection = OpenConnection())
                {
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT id, project_id, device_id, identification_revision, connection_protocol, host, port, user_name, authentication_method, host_key_algorithm, host_key_fingerprint, command_count, created_at_utc FROM collection_tasks WHERE project_id = @projectId ORDER BY created_at_utc, id;";
                        command.Parameters.AddWithValue("@projectId", projectId.ToString());
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                token.ThrowIfCancellationRequested();
                                headers.Add(new StoredCollectionTaskHeader(
                                    CollectionTaskId.Parse(reader.GetString(0)),
                                    ProjectId.Parse(reader.GetString(1)),
                                    DeviceId.Parse(reader.GetString(2)),
                                    reader.GetInt64(3),
                                    ReadEnum<ConnectionProtocol>(reader.GetInt32(4), "collection task protocol"),
                                    reader.GetString(5),
                                    reader.GetInt32(6),
                                    reader.GetString(7),
                                    ReadEnum<SshAuthenticationMethod>(reader.GetInt32(8), "collection task authentication"),
                                    reader.GetString(9),
                                    reader.GetString(10),
                                    reader.GetInt32(11),
                                    ParseUtc(reader.GetString(12))));
                            }
                        }
                    }

                    return headers.Select(header => header.ToRecord(
                        ReadCollectionTaskCommands(connection, header.Id, header.CommandCount, token)))
                        .ToArray();
                }
            },
            cancellationToken);
    }

    public Task<IReadOnlyList<CollectionTaskEventRecord>> GetCollectionTaskEventsAsync(
        CollectionTaskId taskId,
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<IReadOnlyList<CollectionTaskEventRecord>>(
            token =>
            {
                var events = new List<CollectionTaskEventRecord>();
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT revision, state, command_ordinal, event_code, occurred_at_utc FROM collection_task_events WHERE task_id = @taskId ORDER BY revision;";
                    command.Parameters.AddWithValue("@taskId", taskId.ToString());
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            token.ThrowIfCancellationRequested();
                            events.Add(new CollectionTaskEventRecord(
                                taskId,
                                reader.GetInt64(0),
                                ReadEnum<CollectionTaskState>(reader.GetInt32(1), "collection task state"),
                                reader.IsDBNull(2) ? (int?)null : reader.GetInt32(2),
                                reader.GetString(3),
                                ParseUtc(reader.GetString(4))));
                        }
                    }
                }

                return events.ToArray();
            },
            cancellationToken);
    }

    public async Task<int> MarkInterruptedCollectionTasksAsync(
        DateTimeOffset interruptedAt,
        CancellationToken cancellationToken = default)
    {
        if (interruptedAt == default(DateTimeOffset))
        {
            throw new ArgumentException("任务恢复时间不能为空。", nameof(interruptedAt));
        }

        using (var lease = await CollectionTaskWriteLock
            .AcquireAsync(databasePath, cancellationToken)
            .ConfigureAwait(false))
        {
            return await RunDatabaseOperationAsync(
                token =>
                {
                    using (var connection = OpenConnection())
                    using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                    {
                        var active = new List<(CollectionTaskId Id, long Revision)>();
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "SELECT e.task_id, e.revision FROM collection_task_events e INNER JOIN (SELECT task_id, MAX(revision) AS revision FROM collection_task_events GROUP BY task_id) latest ON latest.task_id = e.task_id AND latest.revision = e.revision WHERE e.state IN (2, 3);";
                            using (var reader = command.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    token.ThrowIfCancellationRequested();
                                    active.Add((CollectionTaskId.Parse(reader.GetString(0)), reader.GetInt64(1)));
                                }
                            }
                        }

                        foreach (var item in active)
                        {
                            InsertCollectionTaskEvent(
                                connection,
                                transaction,
                                new CollectionTaskEventRecord(
                                    item.Id,
                                    checked(item.Revision + 1L),
                                    CollectionTaskState.Interrupted,
                                    null,
                                    "ApplicationRestarted",
                                    interruptedAt));
                        }

                        transaction.Commit();
                        return active.Count;
                    }
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public Task<Guid> SaveCommandDraftAsync(
        CommandDraftImportResult draft,
        CancellationToken cancellationToken = default)
    {
        if (draft == null)
        {
            throw new ArgumentNullException(nameof(draft));
        }

        if (draft.IsExecutable || !draft.IsPendingReview)
        {
            throw new InvalidOperationException("导入内容只能作为待校验、禁止执行的命令草稿保存。");
        }

        return RunDatabaseOperationAsync(
            token =>
            {
                var draftId = Guid.NewGuid();
                using (var connection = OpenConnection())
                using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                {
                    token.ThrowIfCancellationRequested();
                    using (var command = connection.CreateCommand())
                    {
                        command.Transaction = transaction;
                        command.CommandText = "INSERT INTO command_drafts(id, source_file_name, raw_sha256, raw_json, imported_at_utc, review_status, is_executable) VALUES(@id, @sourceFileName, @rawSha256, @rawJson, @importedAtUtc, 0, 0);";
                        command.Parameters.AddWithValue("@id", draftId.ToString("D"));
                        command.Parameters.AddWithValue("@sourceFileName", draft.SourceFileName);
                        command.Parameters.AddWithValue("@rawSha256", draft.RawSha256);
                        command.Parameters.AddWithValue("@rawJson", draft.RawJson);
                        command.Parameters.AddWithValue("@importedAtUtc", FormatUtc(draft.ImportedAt));
                        command.ExecuteNonQuery();
                    }

                    foreach (var item in draft.Commands)
                    {
                        token.ThrowIfCancellationRequested();
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "INSERT INTO command_draft_items(draft_id, ordinal, command_id, title, command_text, target_category, declared_risk_level, is_executable) VALUES(@draftId, @ordinal, @commandId, @title, @commandText, @targetCategory, @declaredRiskLevel, 0);";
                            command.Parameters.AddWithValue("@draftId", draftId.ToString("D"));
                            command.Parameters.AddWithValue("@ordinal", item.Index);
                            command.Parameters.AddWithValue("@commandId", (object?)item.Id ?? DBNull.Value);
                            command.Parameters.AddWithValue("@title", (object?)item.Title ?? DBNull.Value);
                            command.Parameters.AddWithValue("@commandText", (object?)item.CommandText ?? DBNull.Value);
                            command.Parameters.AddWithValue("@targetCategory", (object?)item.TargetCategory ?? DBNull.Value);
                            command.Parameters.AddWithValue("@declaredRiskLevel", (object?)item.DeclaredRiskLevel ?? DBNull.Value);
                            command.ExecuteNonQuery();
                        }
                    }

                    for (var ordinal = 0; ordinal < draft.Findings.Count; ordinal++)
                    {
                        token.ThrowIfCancellationRequested();
                        var finding = draft.Findings[ordinal];
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "INSERT INTO command_draft_findings(draft_id, ordinal, severity, code, message, command_index) VALUES(@draftId, @ordinal, @severity, @code, @message, @commandIndex);";
                            command.Parameters.AddWithValue("@draftId", draftId.ToString("D"));
                            command.Parameters.AddWithValue("@ordinal", ordinal);
                            command.Parameters.AddWithValue("@severity", (int)finding.Severity);
                            command.Parameters.AddWithValue("@code", finding.Code);
                            command.Parameters.AddWithValue("@message", finding.Message);
                            command.Parameters.AddWithValue("@commandIndex", (object?)finding.CommandIndex ?? DBNull.Value);
                            command.ExecuteNonQuery();
                        }
                    }

                    token.ThrowIfCancellationRequested();
                    transaction.Commit();
                }

                return draftId;
            },
            cancellationToken);
    }

    public Task<IReadOnlyList<CommandDraftArchiveRecord>> GetCommandDraftsAsync(
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<IReadOnlyList<CommandDraftArchiveRecord>>(
            token =>
            {
                var records = new List<CommandDraftArchiveRecord>();
                var headers = new List<StoredCommandDraftHeader>();
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT id, source_file_name, raw_sha256, raw_json, imported_at_utc FROM command_drafts WHERE review_status = 0 AND is_executable = 0 ORDER BY imported_at_utc DESC, rowid DESC;";
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            token.ThrowIfCancellationRequested();
                            headers.Add(new StoredCommandDraftHeader(
                                Guid.Parse(reader.GetString(0)),
                                reader.GetString(1),
                                reader.GetString(2),
                                reader.GetString(3),
                                ParseUtc(reader.GetString(4))));
                        }
                    }

                    foreach (var header in headers)
                    {
                        records.Add(new CommandDraftArchiveRecord(
                            header.Id,
                            header.SourceFileName,
                            header.RawSha256,
                            header.RawJson,
                            header.ImportedAt,
                            ReadCommandDraftItems(connection, header.Id, token),
                            ReadCommandDraftFindings(connection, header.Id, token)));
                    }
                }

                return records.AsReadOnly();
            },
            cancellationToken);
    }

    private static IReadOnlyList<CommandDraftItem> ReadCommandDraftItems(
        SQLiteConnection connection,
        Guid draftId,
        CancellationToken cancellationToken)
    {
        var items = new List<CommandDraftItem>();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT ordinal, command_id, title, command_text, target_category, declared_risk_level FROM command_draft_items WHERE draft_id = @draftId AND is_executable = 0 ORDER BY ordinal;";
            command.Parameters.AddWithValue("@draftId", draftId.ToString("D"));
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    items.Add(new CommandDraftItem(
                        reader.GetInt32(0),
                        ReadNullableString(reader, 1),
                        ReadNullableString(reader, 2),
                        ReadNullableString(reader, 3),
                        ReadNullableString(reader, 4),
                        ReadNullableString(reader, 5)));
                }
            }
        }

        return items.AsReadOnly();
    }

    private static IReadOnlyList<CommandDraftFinding> ReadCommandDraftFindings(
        SQLiteConnection connection,
        Guid draftId,
        CancellationToken cancellationToken)
    {
        var findings = new List<CommandDraftFinding>();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT severity, code, message, command_index FROM command_draft_findings WHERE draft_id = @draftId ORDER BY ordinal;";
            command.Parameters.AddWithValue("@draftId", draftId.ToString("D"));
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    findings.Add(new CommandDraftFinding(
                        ReadEnum<CommandDraftFindingSeverity>(reader.GetInt32(0), "command draft finding severity"),
                        reader.GetString(1),
                        reader.GetString(2),
                        reader.IsDBNull(3) ? (int?)null : reader.GetInt32(3)));
                }
            }
        }

        return findings.AsReadOnly();
    }

    private sealed class StoredCommandDraftHeader
    {
        public StoredCommandDraftHeader(
            Guid id,
            string sourceFileName,
            string rawSha256,
            string rawJson,
            DateTimeOffset importedAt)
        {
            Id = id;
            SourceFileName = sourceFileName;
            RawSha256 = rawSha256;
            RawJson = rawJson;
            ImportedAt = importedAt;
        }

        public Guid Id { get; }
        public string SourceFileName { get; }
        public string RawSha256 { get; }
        public string RawJson { get; }
        public DateTimeOffset ImportedAt { get; }
    }

    public Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync(
            token =>
            {
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    token.ThrowIfCancellationRequested();
                    command.CommandText = "SELECT COALESCE(MAX(version), 0) FROM schema_version;";
                    return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
                }
            },
            cancellationToken);
    }

    private void InitializeCore(CancellationToken cancellationToken)
    {
        using (var connection = OpenConnection())
        using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
        {
            cancellationToken.ThrowIfCancellationRequested();
            CreateSchemaVersionTable(connection, transaction);
            var appliedVersions = ReadAppliedVersions(connection, transaction, cancellationToken);
            ValidateAppliedMigrationHistory(appliedVersions);
            foreach (var migration in Migrations)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (appliedVersions.Contains(migration.Version))
                {
                    continue;
                }

                ExecuteMigration(connection, transaction, migration);
                using (var command = connection.CreateCommand())
                {
                    command.Transaction = transaction;
                    command.CommandText = "INSERT INTO schema_version(version, applied_at_utc) VALUES(@version, @appliedAtUtc);";
                    command.Parameters.AddWithValue("@version", migration.Version);
                    command.Parameters.AddWithValue("@appliedAtUtc", FormatUtc(DateTimeOffset.UtcNow));
                    command.ExecuteNonQuery();
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
        }
    }

    private SQLiteConnection OpenConnection()
    {
        var connection = new SQLiteConnection(connectionString);
        try
        {
            connection.Open();
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "PRAGMA busy_timeout = " + BusyTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture) + ";";
                command.ExecuteNonQuery();
                command.CommandText = "PRAGMA foreign_keys = ON;";
                command.ExecuteNonQuery();
                command.CommandText = "PRAGMA foreign_keys;";
                if (Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) != 1)
                {
                    throw new InvalidOperationException("SQLite foreign key enforcement could not be enabled.");
                }
            }

            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private static Task RunDatabaseOperationAsync(Action<CancellationToken> operation, CancellationToken cancellationToken)
    {
        return Task.Run(
            () =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                operation(cancellationToken);
            },
            cancellationToken);
    }

    private static Task<TResult> RunDatabaseOperationAsync<TResult>(
        Func<CancellationToken, TResult> operation,
        CancellationToken cancellationToken)
    {
        return Task.Run(
            () =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return operation(cancellationToken);
            },
            cancellationToken);
    }

    private static void CreateSchemaVersionTable(SQLiteConnection connection, SQLiteTransaction transaction)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL PRIMARY KEY, applied_at_utc TEXT NOT NULL);";
            command.ExecuteNonQuery();
        }
    }

    private static HashSet<int> ReadAppliedVersions(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        CancellationToken cancellationToken)
    {
        var versions = new HashSet<int>();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT version FROM schema_version ORDER BY version;";
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    versions.Add(reader.GetInt32(0));
                }
            }
        }

        return versions;
    }

    private static void ValidateAppliedMigrationHistory(ISet<int> appliedVersions)
    {
        var highestAppliedVersion = appliedVersions.Count == 0 ? 0 : appliedVersions.Max();
        if (highestAppliedVersion > Migrations.Length || appliedVersions.Any(version => version < 1))
        {
            throw new InvalidDataException("SQLite database contains an unsupported migration version.");
        }

        for (var expectedVersion = 1; expectedVersion <= highestAppliedVersion; expectedVersion++)
        {
            if (!appliedVersions.Contains(expectedVersion))
            {
                throw new InvalidDataException("SQLite migration history is not sequential.");
            }
        }
    }

    private static void ExecuteMigration(SQLiteConnection connection, SQLiteTransaction transaction, Migration migration)
    {
        var assembly = typeof(SqliteProjectRepository).GetTypeInfo().Assembly;
        using (var stream = assembly.GetManifestResourceStream(migration.ResourceName))
        {
            if (stream == null)
            {
                throw new InvalidOperationException("Required SQLite migration resource was not found.");
            }

            using (var reader = new StreamReader(stream))
            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = reader.ReadToEnd();
                command.ExecuteNonQuery();
            }
        }
    }

    private static string GetEvidenceRootForDevice(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        ProjectId projectId,
        DeviceId deviceId)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT p.evidence_root FROM devices d INNER JOIN projects p ON p.id = d.project_id WHERE d.id = @deviceId AND d.project_id = @projectId;";
            command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
            command.Parameters.AddWithValue("@projectId", projectId.ToString());
            var evidenceRoot = command.ExecuteScalar() as string;
            if (evidenceRoot == null)
            {
                throw new InvalidOperationException("Execution device does not belong to the specified project.");
            }

            return evidenceRoot;
        }
    }

    private static NormalizedEvidence NormalizeEvidence(ExecutionRecord record, string evidenceRoot)
    {
        var rawOutputPath = record.RawOutputPath == null
            ? null
            : NormalizeRelativeEvidencePath(evidenceRoot, record.RawOutputPath, nameof(record.RawOutputPath));
        var images = new List<NormalizedEvidenceImage>();
        foreach (var imagePath in record.EvidenceImagePaths)
        {
            images.Add(new NormalizedEvidenceImage(
                NormalizeRelativeEvidencePath(evidenceRoot, imagePath, nameof(record.EvidenceImagePaths)),
                record.EvidenceImageSha256s[imagePath]));
        }

        return new NormalizedEvidence(rawOutputPath, images);
    }

    private static string NormalizeRelativeEvidencePath(string evidenceRoot, string path, string parameterName)
    {
        var normalizedRoot = WindowsEvidenceRootPolicy.Normalize(evidenceRoot, nameof(evidenceRoot));
        var rootWithSeparator = WindowsEvidenceRootPolicy.EnsureTrailingSeparator(normalizedRoot);
        var combinedPath = WindowsEvidenceRootPolicy.ResolveContainedPath(
            normalizedRoot,
            path,
            parameterName);
        return combinedPath.Substring(rootWithSeparator.Length);
    }

    private static void InsertExecution(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        string executionId,
        ExecutionRecord record,
        string? normalizedRawOutputPath)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO executions(id, project_id, device_id, connection_protocol, command_pack_version, command_id, command_text, started_at_utc, completed_at_utc, status, exit_code, raw_output_path, raw_output_sha256, error_text) VALUES(@id, @projectId, @deviceId, @connectionProtocol, @commandPackVersion, @commandId, @commandText, @startedAtUtc, @completedAtUtc, @status, @exitCode, @rawOutputPath, @rawOutputSha256, @errorText);";
            command.Parameters.AddWithValue("@id", executionId);
            command.Parameters.AddWithValue("@projectId", record.ProjectId);
            command.Parameters.AddWithValue("@deviceId", record.DeviceId);
            command.Parameters.AddWithValue("@connectionProtocol", (int)record.ConnectionProtocol);
            command.Parameters.AddWithValue("@commandPackVersion", record.CommandPackVersion);
            command.Parameters.AddWithValue("@commandId", record.CommandId);
            command.Parameters.AddWithValue("@commandText", record.CommandText);
            command.Parameters.AddWithValue("@startedAtUtc", FormatUtc(record.StartedAt));
            command.Parameters.AddWithValue("@completedAtUtc", record.CompletedAt.HasValue ? (object)FormatUtc(record.CompletedAt.Value) : DBNull.Value);
            command.Parameters.AddWithValue("@status", (int)record.Status);
            command.Parameters.AddWithValue("@exitCode", record.ExitCode.HasValue ? (object)record.ExitCode.Value : DBNull.Value);
            command.Parameters.AddWithValue("@rawOutputPath", (object?)normalizedRawOutputPath ?? DBNull.Value);
            command.Parameters.AddWithValue("@rawOutputSha256", (object?)record.RawOutputSha256 ?? DBNull.Value);
            command.Parameters.AddWithValue("@errorText", (object?)record.ErrorText ?? DBNull.Value);
            command.ExecuteNonQuery();
        }
    }

    private static void InsertEvidenceFiles(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        string executionId,
        ProjectId projectId,
        DeviceId deviceId,
        ExecutionRecord record,
        NormalizedEvidence evidence)
    {
        var ordinal = 0;
        if (evidence.RawOutputPath != null && record.RawOutputSha256 != null)
        {
            InsertEvidenceFile(
                connection, transaction, executionId, projectId, deviceId, evidence.RawOutputPath,
                record.RawOutputSha256, EvidenceFileKind.RawOutput, ordinal++, record.CompletedAt ?? record.StartedAt);
        }

        foreach (var image in evidence.Images)
        {
            InsertEvidenceFile(
                connection, transaction, executionId, projectId, deviceId, image.RelativePath,
                image.Sha256, EvidenceFileKind.EvidenceImage, ordinal++, record.CompletedAt ?? record.StartedAt);
        }
    }

    private static void InsertEvidenceFile(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        string executionId,
        ProjectId projectId,
        DeviceId deviceId,
        string relativePath,
        string sha256,
        EvidenceFileKind kind,
        int ordinal,
        DateTimeOffset createdAt)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO evidence_files(id, execution_id, project_id, device_id, relative_path, sha256, evidence_kind, ordinal, created_at_utc) VALUES(@id, @executionId, @projectId, @deviceId, @relativePath, @sha256, @evidenceKind, @ordinal, @createdAtUtc);";
            command.Parameters.AddWithValue("@id", Guid.NewGuid().ToString("D"));
            command.Parameters.AddWithValue("@executionId", executionId);
            command.Parameters.AddWithValue("@projectId", projectId.ToString());
            command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
            command.Parameters.AddWithValue("@relativePath", relativePath);
            command.Parameters.AddWithValue("@sha256", sha256);
            command.Parameters.AddWithValue("@evidenceKind", (int)kind);
            command.Parameters.AddWithValue("@ordinal", ordinal);
            command.Parameters.AddWithValue("@createdAtUtc", FormatUtc(createdAt));
            command.ExecuteNonQuery();
        }
    }

    private static SshHostKeyTrustRecord ReadSshHostKeyTrust(
        DeviceId deviceId,
        SshEndpointIdentity endpoint,
        SQLiteDataReader reader)
    {
        var state = ReadEnum<HostKeyTrustState>(reader.GetInt32(2), "SSH host key trust state");
        var algorithm = ReadNullableString(reader, 3);
        var fingerprint = ReadNullableString(reader, 4);
        var observedAlgorithm = ReadNullableString(reader, 5);
        var observedFingerprint = ReadNullableString(reader, 6);
        var observedAt = ReadNullableUtc(reader, 7);
        var confirmedAt = ReadNullableUtc(reader, 8);
        var confirmationSource = ReadNullableString(reader, 9);
        var previousAlgorithm = ReadNullableString(reader, 10);
        var previousFingerprint = ReadNullableString(reader, 11);
        var previousConfirmedAt = ReadNullableUtc(reader, 12);
        var previousConfirmationSource = ReadNullableString(reader, 13);
        var revision = reader.GetInt64(14);
        if (revision <= 0)
        {
            throw new InvalidDataException("Stored SSH host key trust revision is invalid.");
        }

        var trust = RebuildSshHostKeyTrust(
            endpoint,
            state,
            algorithm,
            fingerprint,
            observedAlgorithm,
            observedFingerprint,
            observedAt,
            confirmedAt,
            confirmationSource,
            previousAlgorithm,
            previousFingerprint,
            previousConfirmedAt,
            previousConfirmationSource);
        return new SshHostKeyTrustRecord(deviceId, trust, revision);
    }

    private static HostKeyTrust RebuildSshHostKeyTrust(
        SshEndpointIdentity endpoint,
        HostKeyTrustState state,
        string? algorithm,
        string? fingerprint,
        string? observedAlgorithm,
        string? observedFingerprint,
        DateTimeOffset? observedAt,
        DateTimeOffset? confirmedAt,
        string? confirmationSource,
        string? previousAlgorithm,
        string? previousFingerprint,
        DateTimeOffset? previousConfirmedAt,
        string? previousConfirmationSource)
    {
        var coordinator = HostKeyTrustServices.CreateCoordinator();
        var trust = HostKeyTrust.Unconfigured(endpoint);
        if (state == HostKeyTrustState.Unconfigured)
        {
            return trust;
        }

        if (state == HostKeyTrustState.AwaitingConfirmation && algorithm == null)
        {
            return coordinator.RecordObservation(
                coordinator.BeginProbe(trust),
                RequireStoredValue(observedAlgorithm, "observed algorithm"),
                RequireStoredValue(observedFingerprint, "observed fingerprint"),
                RequireStoredDate(observedAt, "observed time"));
        }

        if (previousAlgorithm != null || previousFingerprint != null || previousConfirmedAt.HasValue || previousConfirmationSource != null)
        {
            var priorConfirmedAt = RequireStoredDate(previousConfirmedAt, "previous confirmed time");
            trust = PinSshHostKey(
                coordinator,
                trust,
                RequireStoredValue(previousAlgorithm, "previous algorithm"),
                RequireStoredValue(previousFingerprint, "previous fingerprint"),
                priorConfirmedAt,
                priorConfirmedAt,
                RequireStoredValue(previousConfirmationSource, "previous confirmation source"));
            trust = coordinator.RecordMismatchObservation(
                trust,
                RequireStoredValue(algorithm, "algorithm"),
                RequireStoredValue(fingerprint, "fingerprint"),
                state == HostKeyTrustState.Pinned
                    ? RequireStoredDate(observedAt, "observed time")
                    : RequireStoredDate(confirmedAt, "confirmed time"));
            trust = coordinator.BeginReconfirmation(trust);
            trust = coordinator.Confirm(
                trust,
                RequireStoredDate(confirmedAt, "confirmed time"),
                RequireStoredValue(confirmationSource, "confirmation source"));
        }
        else
        {
            var pinConfirmedAt = RequireStoredDate(confirmedAt, "confirmed time");
            var pinObservedAt = state == HostKeyTrustState.Pinned
                ? RequireStoredDate(observedAt, "observed time")
                : pinConfirmedAt;
            trust = PinSshHostKey(
                coordinator,
                trust,
                RequireStoredValue(algorithm, "algorithm"),
                RequireStoredValue(fingerprint, "fingerprint"),
                pinObservedAt,
                pinConfirmedAt,
                RequireStoredValue(confirmationSource, "confirmation source"));
        }

        if (state == HostKeyTrustState.Pinned)
        {
            return trust;
        }

        if (state == HostKeyTrustState.Verified)
        {
            return coordinator.RecordMatchingObservation(
                trust,
                RequireStoredDate(observedAt, "observed time"));
        }

        if (state == HostKeyTrustState.MismatchBlocked)
        {
            return coordinator.RecordMismatchObservation(
                trust,
                RequireStoredValue(observedAlgorithm, "observed algorithm"),
                RequireStoredValue(observedFingerprint, "observed fingerprint"),
                RequireStoredDate(observedAt, "observed time"));
        }

        if (state == HostKeyTrustState.AwaitingConfirmation)
        {
            trust = coordinator.RecordMismatchObservation(
                trust,
                RequireStoredValue(observedAlgorithm, "observed algorithm"),
                RequireStoredValue(observedFingerprint, "observed fingerprint"),
                RequireStoredDate(observedAt, "observed time"));
            return coordinator.BeginReconfirmation(trust);
        }

        throw new InvalidDataException("Stored SSH host key trust state cannot be reconstructed.");
    }

    private static HostKeyTrust PinSshHostKey(
        HostKeyTrustCoordinator coordinator,
        HostKeyTrust unconfigured,
        string algorithm,
        string fingerprint,
        DateTimeOffset observedAt,
        DateTimeOffset confirmedAt,
        string confirmationSource)
    {
        var awaitingConfirmation = coordinator.RecordObservation(
            coordinator.BeginProbe(unconfigured), algorithm, fingerprint, observedAt);
        return coordinator.Confirm(awaitingConfirmation, confirmedAt, confirmationSource);
    }

    private static void EnsureTrustEndpointMatchesDevice(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        DeviceId deviceId,
        SshEndpointIdentity endpoint)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT host, port FROM devices WHERE id = @deviceId;";
            command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
            using (var reader = command.ExecuteReader())
            {
                if (!reader.Read())
                {
                    throw new InvalidOperationException("SSH 主机指纹信任对应的设备不存在。");
                }

                var storedEndpoint = new SshEndpointIdentity(reader.GetString(0), reader.GetInt32(1));
                if (!storedEndpoint.Equals(endpoint))
                {
                    throw new ArgumentException("SSH 主机指纹信任与设备端点不一致。", nameof(endpoint));
                }
            }
        }
    }

    private static int InsertSshHostKeyTrust(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        DeviceId deviceId,
        HostKeyTrust trust,
        long revision)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                "INSERT INTO ssh_host_key_trust(device_id, state, algorithm, fingerprint, " +
                "observed_algorithm, observed_fingerprint, observed_at_utc, confirmed_at_utc, " +
                "confirmation_source, previous_algorithm, previous_fingerprint, " +
                "previous_confirmed_at_utc, previous_confirmation_source, revision) " +
                "SELECT @deviceId, @state, @algorithm, @fingerprint, @observedAlgorithm, " +
                "@observedFingerprint, @observedAtUtc, @confirmedAtUtc, @confirmationSource, " +
                "@previousAlgorithm, @previousFingerprint, @previousConfirmedAtUtc, " +
                "@previousConfirmationSource, @revision " +
                "WHERE NOT EXISTS (SELECT 1 FROM ssh_host_key_trust WHERE device_id = @deviceId);";
            AddSshHostKeyTrustParameters(command, deviceId, trust, revision);
            return command.ExecuteNonQuery();
        }
    }

    private static int UpdateSshHostKeyTrust(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        DeviceId deviceId,
        HostKeyTrust trust,
        long expectedRevision,
        long revision)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                "UPDATE ssh_host_key_trust SET state = @state, algorithm = @algorithm, " +
                "fingerprint = @fingerprint, observed_algorithm = @observedAlgorithm, " +
                "observed_fingerprint = @observedFingerprint, observed_at_utc = @observedAtUtc, " +
                "confirmed_at_utc = @confirmedAtUtc, confirmation_source = @confirmationSource, " +
                "previous_algorithm = @previousAlgorithm, previous_fingerprint = @previousFingerprint, " +
                "previous_confirmed_at_utc = @previousConfirmedAtUtc, " +
                "previous_confirmation_source = @previousConfirmationSource, revision = @revision " +
                "WHERE device_id = @deviceId AND revision = @expectedRevision;";
            AddSshHostKeyTrustParameters(command, deviceId, trust, revision);
            command.Parameters.AddWithValue("@expectedRevision", expectedRevision);
            return command.ExecuteNonQuery();
        }
    }

    private static void AddSshHostKeyTrustParameters(
        SQLiteCommand command,
        DeviceId deviceId,
        HostKeyTrust trust,
        long revision)
    {
        command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
        command.Parameters.AddWithValue("@state", (int)trust.State);
        command.Parameters.AddWithValue("@algorithm", (object?)trust.Algorithm ?? DBNull.Value);
        command.Parameters.AddWithValue("@fingerprint", (object?)trust.Fingerprint ?? DBNull.Value);
        command.Parameters.AddWithValue("@observedAlgorithm", (object?)trust.ObservedAlgorithm ?? DBNull.Value);
        command.Parameters.AddWithValue("@observedFingerprint", (object?)trust.ObservedFingerprint ?? DBNull.Value);
        command.Parameters.AddWithValue("@observedAtUtc", FormatNullableUtc(trust.ObservedAt));
        command.Parameters.AddWithValue("@confirmedAtUtc", FormatNullableUtc(trust.ConfirmedAt));
        command.Parameters.AddWithValue("@confirmationSource", (object?)trust.ConfirmationSource ?? DBNull.Value);
        command.Parameters.AddWithValue("@previousAlgorithm", (object?)trust.PreviousAlgorithm ?? DBNull.Value);
        command.Parameters.AddWithValue("@previousFingerprint", (object?)trust.PreviousFingerprint ?? DBNull.Value);
        command.Parameters.AddWithValue("@previousConfirmedAtUtc", FormatNullableUtc(trust.PreviousConfirmedAt));
        command.Parameters.AddWithValue("@previousConfirmationSource", (object?)trust.PreviousConfirmationSource ?? DBNull.Value);
        command.Parameters.AddWithValue("@revision", revision);
    }

    private static void EnsurePersistableHostKeyTrustState(HostKeyTrustState state)
    {
        if (state == HostKeyTrustState.AwaitingProbe || !Enum.IsDefined(typeof(HostKeyTrustState), state))
        {
            throw new ArgumentException("瞬时的 SSH 主机指纹探测状态不能持久化。", nameof(state));
        }
    }

    private static string RequireStoredValue(string? value, string description)
    {
        if (value == null)
        {
            throw new InvalidDataException("Stored SSH host key trust " + description + " is missing.");
        }

        return value;
    }

    private static DateTimeOffset RequireStoredDate(DateTimeOffset? value, string description)
    {
        if (!value.HasValue)
        {
            throw new InvalidDataException("Stored SSH host key trust " + description + " is missing.");
        }

        return value.Value;
    }

    private static string? ReadNullableString(SQLiteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static void AddDeviceIdentificationParameters(
        SQLiteCommand command,
        DeviceIdentificationRecord record)
    {
        command.Parameters.AddWithValue("@deviceId", record.DeviceId.ToString());
        command.Parameters.AddWithValue("@revision", record.Revision);
        command.Parameters.AddWithValue("@targetCategory", (int)record.Category);
        command.Parameters.AddWithValue("@vendor", (object?)record.Vendor ?? DBNull.Value);
        command.Parameters.AddWithValue("@productFamily", (object?)record.ProductFamily ?? DBNull.Value);
        command.Parameters.AddWithValue("@model", (object?)record.Model ?? DBNull.Value);
        command.Parameters.AddWithValue("@version", (object?)record.Version ?? DBNull.Value);
        command.Parameters.AddWithValue("@evidence", record.Evidence);
        command.Parameters.AddWithValue("@confidence", record.Confidence);
        command.Parameters.AddWithValue("@wasUserConfirmed", record.WasUserConfirmed ? 1 : 0);
        command.Parameters.AddWithValue(
            "@confirmationSource",
            (object?)record.ConfirmationSource ?? DBNull.Value);
        command.Parameters.AddWithValue("@recordedAtUtc", FormatUtc(record.RecordedAt));
    }

    private static void InsertPendingIdentificationCandidate(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        Guid batchId,
        int ordinal,
        DetectionCandidate candidate)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO pending_device_identification_candidates(batch_id, ordinal, target_category, vendor, product_family, model, version, detection_evidence, confidence) VALUES(@batchId, @ordinal, @targetCategory, @vendor, @productFamily, @model, @version, @evidence, @confidence);";
            command.Parameters.AddWithValue("@batchId", batchId.ToString("D"));
            command.Parameters.AddWithValue("@ordinal", ordinal);
            command.Parameters.AddWithValue("@targetCategory", (int)candidate.Category);
            command.Parameters.AddWithValue("@vendor", (object?)candidate.Vendor ?? DBNull.Value);
            command.Parameters.AddWithValue("@productFamily", (object?)candidate.ProductFamily ?? DBNull.Value);
            command.Parameters.AddWithValue("@model", (object?)candidate.Model ?? DBNull.Value);
            command.Parameters.AddWithValue("@version", (object?)candidate.Version ?? DBNull.Value);
            command.Parameters.AddWithValue("@evidence", candidate.Evidence);
            command.Parameters.AddWithValue("@confidence", candidate.Confidence);
            command.ExecuteNonQuery();
        }
    }

    private static void InsertPendingIdentificationResolution(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        DeviceId deviceId,
        Guid batchId,
        PendingIdentificationResolution resolution,
        DateTimeOffset resolvedAt)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO pending_device_identification_resolutions(batch_id, resolution, resolved_at_utc) SELECT b.batch_id, @resolution, @resolvedAtUtc FROM pending_device_identification_batches b WHERE b.batch_id = @batchId AND b.device_id = @deviceId AND NOT EXISTS (SELECT 1 FROM pending_device_identification_resolutions r WHERE r.batch_id = b.batch_id);";
            command.Parameters.AddWithValue("@batchId", batchId.ToString("D"));
            command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
            command.Parameters.AddWithValue("@resolution", (int)resolution);
            command.Parameters.AddWithValue("@resolvedAtUtc", FormatUtc(resolvedAt));
            if (command.ExecuteNonQuery() != 1)
            {
                throw new InvalidOperationException("待确认识别批次不存在、已处理或不属于当前设备。");
            }
        }
    }

    private static DeviceIdentificationRecord ReadDeviceIdentification(SQLiteDataReader reader)
    {
        return new DeviceIdentificationRecord(
            DeviceId.Parse(reader.GetString(0)),
            reader.GetInt64(1),
            ReadEnum<TargetCategory>(reader.GetInt32(2), "device identification target category"),
            ReadNullableString(reader, 3),
            ReadNullableString(reader, 4),
            ReadNullableString(reader, 5),
            ReadNullableString(reader, 6),
            reader.GetString(7),
            reader.GetDouble(8),
            reader.GetInt32(9) == 1,
            ReadNullableString(reader, 10),
            ParseUtc(reader.GetString(11)));
    }

    private static DateTimeOffset? ReadNullableUtc(SQLiteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? (DateTimeOffset?)null : ParseUtc(reader.GetString(ordinal));
    }

    private static object FormatNullableUtc(DateTimeOffset? value)
    {
        return value.HasValue ? (object)FormatUtc(value.Value) : DBNull.Value;
    }

    private static StoredExecution ReadStoredExecution(SQLiteDataReader reader)
    {
        return new StoredExecution(
            reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetInt32(3), reader.GetString(4),
            reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.IsDBNull(8) ? null : reader.GetString(8),
            reader.GetInt32(9), reader.IsDBNull(10) ? (int?)null : reader.GetInt32(10),
            reader.IsDBNull(11) ? null : reader.GetString(11), reader.IsDBNull(12) ? null : reader.GetString(12),
            reader.IsDBNull(13) ? null : reader.GetString(13));
    }

    private static ExecutionRecord ReadExecution(
        SQLiteConnection connection,
        StoredExecution storedExecution,
        CancellationToken cancellationToken)
    {
        var evidencePaths = new List<string>();
        var evidenceHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT relative_path, sha256 FROM evidence_files WHERE execution_id = @executionId AND evidence_kind = @evidenceKind ORDER BY ordinal;";
            command.Parameters.AddWithValue("@executionId", storedExecution.Id);
            command.Parameters.AddWithValue("@evidenceKind", (int)EvidenceFileKind.EvidenceImage);
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var path = reader.GetString(0);
                    evidencePaths.Add(path);
                    evidenceHashes.Add(path, reader.GetString(1));
                }
            }
        }

        return new ExecutionRecord(
            storedExecution.ProjectId,
            storedExecution.DeviceId,
            ReadEnum<ConnectionProtocol>(storedExecution.ConnectionProtocol, "connection protocol"),
            storedExecution.CommandPackVersion,
            storedExecution.CommandId,
            storedExecution.CommandText,
            ParseUtc(storedExecution.StartedAtUtc),
            storedExecution.CompletedAtUtc == null ? (DateTimeOffset?)null : ParseUtc(storedExecution.CompletedAtUtc),
            ReadEnum<ExecutionStatus>(storedExecution.Status, "execution status"),
            storedExecution.ExitCode,
            storedExecution.RawOutputPath,
            storedExecution.RawOutputSha256,
            evidencePaths,
            evidenceHashes,
            storedExecution.ErrorText);
    }

    private static IReadOnlyList<CollectionTaskCommandSnapshot> ReadCollectionTaskCommands(
        SQLiteConnection connection,
        CollectionTaskId taskId,
        int expectedCount,
        CancellationToken cancellationToken)
    {
        var commands = new List<CollectionTaskCommandSnapshot>();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT ordinal, command_pack_id, command_pack_version, command_pack_sha256, command_id, command_text, check_item, result_description, risk_level, is_optional, safety_validated_at_utc FROM collection_task_commands WHERE task_id = @taskId ORDER BY ordinal;";
            command.Parameters.AddWithValue("@taskId", taskId.ToString());
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    commands.Add(new CollectionTaskCommandSnapshot(
                        reader.GetInt32(0),
                        reader.GetString(1),
                        reader.GetString(2),
                        reader.GetString(3),
                        reader.GetString(4),
                        reader.GetString(5),
                        reader.GetString(6),
                        reader.GetString(7),
                        ReadEnum<CommandRiskLevel>(reader.GetInt32(8), "collection task risk level"),
                        reader.GetInt32(9) == 1,
                        ParseUtc(reader.GetString(10))));
                }
            }
        }

        if (commands.Count != expectedCount)
        {
            throw new InvalidDataException("采集任务命令快照不完整，已阻止读取。");
        }

        return commands;
    }

    private static void InsertCollectionTaskEvent(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        CollectionTaskEventRecord record)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO collection_task_events(task_id, revision, state, command_ordinal, event_code, occurred_at_utc) VALUES(@taskId, @revision, @state, @commandOrdinal, @eventCode, @occurredAtUtc);";
            command.Parameters.AddWithValue("@taskId", record.TaskId.ToString());
            command.Parameters.AddWithValue("@revision", record.Revision);
            command.Parameters.AddWithValue("@state", (int)record.State);
            command.Parameters.AddWithValue("@commandOrdinal", (object?)record.CommandOrdinal ?? DBNull.Value);
            command.Parameters.AddWithValue("@eventCode", record.EventCode);
            command.Parameters.AddWithValue("@occurredAtUtc", FormatUtc(record.OccurredAt));
            command.ExecuteNonQuery();
        }
    }

    private static bool CanTransitionCollectionTask(
        CollectionTaskState current,
        CollectionTaskState next)
    {
        switch (current)
        {
            case CollectionTaskState.Ready:
                return next == CollectionTaskState.Running;
            case CollectionTaskState.Running:
                return next == CollectionTaskState.Stopping
                    || next == CollectionTaskState.Completed
                    || next == CollectionTaskState.Failed
                    || next == CollectionTaskState.Stopped
                    || next == CollectionTaskState.Interrupted;
            case CollectionTaskState.Stopping:
                return next == CollectionTaskState.Stopped
                    || next == CollectionTaskState.Failed
                    || next == CollectionTaskState.Interrupted;
            default:
                return false;
        }
    }

    private static TEnum ReadEnum<TEnum>(int value, string description)
        where TEnum : struct
    {
        if (!Enum.IsDefined(typeof(TEnum), value))
        {
            throw new InvalidDataException("Stored " + description + " is invalid.");
        }

        return (TEnum)(object)value;
    }

    private static string FormatUtc(DateTimeOffset value)
    {
        return value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    }

    private static DateTimeOffset ParseUtc(string value)
    {
        return DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime();
    }

    private sealed class Migration
    {
        public Migration(int version, string resourceName)
        {
            Version = version;
            ResourceName = resourceName;
        }

        public int Version { get; }
        public string ResourceName { get; }
    }

    private sealed class StoredCollectionTaskHeader
    {
        public StoredCollectionTaskHeader(
            CollectionTaskId id,
            ProjectId projectId,
            DeviceId deviceId,
            long identificationRevision,
            ConnectionProtocol connectionProtocol,
            string host,
            int port,
            string userName,
            SshAuthenticationMethod authenticationMethod,
            string hostKeyAlgorithm,
            string hostKeyFingerprint,
            int commandCount,
            DateTimeOffset createdAt)
        {
            Id = id;
            ProjectId = projectId;
            DeviceId = deviceId;
            IdentificationRevision = identificationRevision;
            ConnectionProtocol = connectionProtocol;
            Host = host;
            Port = port;
            UserName = userName;
            AuthenticationMethod = authenticationMethod;
            HostKeyAlgorithm = hostKeyAlgorithm;
            HostKeyFingerprint = hostKeyFingerprint;
            CommandCount = commandCount;
            CreatedAt = createdAt;
        }

        public CollectionTaskId Id { get; }
        public ProjectId ProjectId { get; }
        public DeviceId DeviceId { get; }
        public long IdentificationRevision { get; }
        public ConnectionProtocol ConnectionProtocol { get; }
        public string Host { get; }
        public int Port { get; }
        public string UserName { get; }
        public SshAuthenticationMethod AuthenticationMethod { get; }
        public string HostKeyAlgorithm { get; }
        public string HostKeyFingerprint { get; }
        public int CommandCount { get; }
        public DateTimeOffset CreatedAt { get; }

        public CollectionTaskRecord ToRecord(IReadOnlyList<CollectionTaskCommandSnapshot> commands)
        {
            return new CollectionTaskRecord(
                Id,
                ProjectId,
                DeviceId,
                IdentificationRevision,
                ConnectionProtocol,
                Host,
                Port,
                UserName,
                AuthenticationMethod,
                HostKeyAlgorithm,
                HostKeyFingerprint,
                commands,
                CreatedAt);
        }
    }

    private sealed class NormalizedEvidence
    {
        public NormalizedEvidence(string? rawOutputPath, IReadOnlyList<NormalizedEvidenceImage> images)
        {
            RawOutputPath = rawOutputPath;
            Images = images;
        }

        public string? RawOutputPath { get; }
        public IReadOnlyList<NormalizedEvidenceImage> Images { get; }
    }

    private sealed class NormalizedEvidenceImage
    {
        public NormalizedEvidenceImage(string relativePath, string sha256)
        {
            RelativePath = relativePath;
            Sha256 = sha256;
        }

        public string RelativePath { get; }
        public string Sha256 { get; }
    }

    private sealed class StoredExecution
    {
        public StoredExecution(
            string id,
            string projectId,
            string deviceId,
            int connectionProtocol,
            string commandPackVersion,
            string commandId,
            string commandText,
            string startedAtUtc,
            string? completedAtUtc,
            int status,
            int? exitCode,
            string? rawOutputPath,
            string? rawOutputSha256,
            string? errorText)
        {
            Id = id;
            ProjectId = projectId;
            DeviceId = deviceId;
            ConnectionProtocol = connectionProtocol;
            CommandPackVersion = commandPackVersion;
            CommandId = commandId;
            CommandText = commandText;
            StartedAtUtc = startedAtUtc;
            CompletedAtUtc = completedAtUtc;
            Status = status;
            ExitCode = exitCode;
            RawOutputPath = rawOutputPath;
            RawOutputSha256 = rawOutputSha256;
            ErrorText = errorText;
        }

        public string Id { get; }
        public string ProjectId { get; }
        public string DeviceId { get; }
        public int ConnectionProtocol { get; }
        public string CommandPackVersion { get; }
        public string CommandId { get; }
        public string CommandText { get; }
        public string StartedAtUtc { get; }
        public string? CompletedAtUtc { get; }
        public int Status { get; }
        public int? ExitCode { get; }
        public string? RawOutputPath { get; }
        public string? RawOutputSha256 { get; }
        public string? ErrorText { get; }
    }
}
