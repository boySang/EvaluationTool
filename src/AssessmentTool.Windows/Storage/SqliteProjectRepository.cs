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

namespace AssessmentTool.Windows.Storage;

public sealed class SqliteProjectRepository : IProjectRepository
{
    private const int BusyTimeoutMilliseconds = 5000;

    private static readonly Migration[] Migrations =
    {
        new Migration(1, "AssessmentTool.Windows.Storage.Migrations.001_initial.sql")
    };

    private static readonly KeyedAsyncLock InitializationLock =
        new KeyedAsyncLock(StringComparer.OrdinalIgnoreCase);

    private readonly string connectionString;
    private readonly string databasePath;

    internal static int InitializationLockCount => InitializationLock.Count;

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
                    NormalizeEvidenceRoot(evidenceRoot),
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
        return RunDatabaseOperationAsync(
            token =>
            {
                var device = new DeviceRecord(
                    DeviceId.New(), projectId, displayName, host, port, credentialReference, DateTimeOffset.UtcNow);
                using (var connection = OpenConnection())
                using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                using (var command = connection.CreateCommand())
                {
                    token.ThrowIfCancellationRequested();
                    command.Transaction = transaction;
                    command.CommandText = "INSERT INTO devices(id, project_id, display_name, host, port, credential_reference, created_at_utc) VALUES(@id, @projectId, @displayName, @host, @port, @credentialReference, @createdAtUtc);";
                    command.Parameters.AddWithValue("@id", device.Id.ToString());
                    command.Parameters.AddWithValue("@projectId", device.ProjectId.ToString());
                    command.Parameters.AddWithValue("@displayName", device.DisplayName);
                    command.Parameters.AddWithValue("@host", device.Host);
                    command.Parameters.AddWithValue("@port", device.Port);
                    command.Parameters.AddWithValue("@credentialReference", device.CredentialReference.ToString());
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
                    command.CommandText = "SELECT id, project_id, display_name, host, port, credential_reference, created_at_utc FROM devices WHERE project_id = @projectId ORDER BY created_at_utc, id;";
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
                                CredentialReference.Parse(reader.GetString(5)),
                                ParseUtc(reader.GetString(6))));
                        }
                    }
                }

                return devices.AsReadOnly();
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

    private static string NormalizeEvidenceRoot(string evidenceRoot)
    {
        if (string.IsNullOrWhiteSpace(evidenceRoot) || evidenceRoot.IndexOf('\0') >= 0)
        {
            throw new ArgumentException("Evidence root cannot be blank or contain NUL.", nameof(evidenceRoot));
        }

        if (!IsFullyQualifiedWindowsPath(evidenceRoot))
        {
            throw new ArgumentException("Evidence root must be a fully-qualified drive or UNC path.", nameof(evidenceRoot));
        }

        var fullPath = Path.GetFullPath(evidenceRoot);
        if (!Path.IsPathRooted(fullPath))
        {
            throw new ArgumentException("Evidence root must be an absolute Windows path.", nameof(evidenceRoot));
        }

        var pathRoot = Path.GetPathRoot(fullPath);
        return string.Equals(fullPath, pathRoot, StringComparison.OrdinalIgnoreCase)
            ? fullPath
            : fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static bool IsFullyQualifiedWindowsPath(string path)
    {
        var isDriveAbsolute = path.Length >= 3
            && char.IsLetter(path[0])
            && path[1] == ':'
            && (path[2] == '\\' || path[2] == '/');
        if (isDriveAbsolute)
        {
            return true;
        }

        var isUnc = path.StartsWith("\\\\", StringComparison.Ordinal)
            || path.StartsWith("//", StringComparison.Ordinal);
        if (!isUnc
            || path.StartsWith("\\\\?\\", StringComparison.Ordinal)
            || path.StartsWith("\\\\.\\", StringComparison.Ordinal)
            || path.StartsWith("//?/", StringComparison.Ordinal)
            || path.StartsWith("//./", StringComparison.Ordinal))
        {
            return false;
        }

        var uncSegments = path.Substring(2).Split(new[] { '/', '\\' }, StringSplitOptions.None);
        return uncSegments.Length >= 2
            && !string.IsNullOrWhiteSpace(uncSegments[0])
            && !string.IsNullOrWhiteSpace(uncSegments[1])
            && uncSegments[0] != "."
            && uncSegments[0] != ".."
            && uncSegments[1] != "."
            && uncSegments[1] != "..";
    }

    private static string NormalizeRelativeEvidencePath(string evidenceRoot, string path, string parameterName)
    {
        var normalizedRelativePath = WindowsEvidenceRelativePathPolicy.Normalize(path, parameterName);

        var normalizedRoot = Path.GetFullPath(evidenceRoot);
        var rootWithSeparator = normalizedRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        var combinedPath = Path.GetFullPath(Path.Combine(normalizedRoot, normalizedRelativePath));
        if (!combinedPath.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Evidence path resolves outside the project evidence root.", parameterName);
        }

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
