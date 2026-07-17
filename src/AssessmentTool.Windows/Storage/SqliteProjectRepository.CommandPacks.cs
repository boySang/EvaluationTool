using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Commands;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Windows.Storage;

public sealed partial class SqliteProjectRepository
{
    private static readonly KeyedAsyncLock PublishedCommandPackWriteLock =
        new KeyedAsyncLock(StringComparer.OrdinalIgnoreCase);
    private static readonly KeyedAsyncLock ProjectCommandPackLockWriteLock =
        new KeyedAsyncLock(StringComparer.OrdinalIgnoreCase);

    internal static int PublishedCommandPackWriteLockCount => PublishedCommandPackWriteLock.Count;
    internal static int ProjectCommandPackLockWriteLockCount => ProjectCommandPackLockWriteLock.Count;

    public async Task<PublishedCommandPackRecord> PublishCommandPackAsync(
        PublishedCommandPackRecord record,
        CancellationToken cancellationToken = default)
    {
        if (record == null)
        {
            throw new ArgumentNullException(nameof(record));
        }

        var computedHash = ComputeSha256(record.RawJson);
        if (!string.Equals(record.RawSha256, computedHash, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Published command pack SHA-256 does not match its raw JSON.");
        }

        CommandPack verifiedPack;
        try
        {
            verifiedPack = new CommandPackLoader().Load(
                new UTF8Encoding(false, true).GetBytes(record.RawJson),
                record.RawSha256);
        }
        catch (Exception exception) when (!(exception is OperationCanceledException))
        {
            throw new InvalidDataException("Published command pack did not pass the formal read-only loader.", exception);
        }

        if (!string.Equals(verifiedPack.Id, record.PackId, StringComparison.Ordinal)
            || !string.Equals(verifiedPack.Name, record.PackName, StringComparison.Ordinal)
            || !string.Equals(verifiedPack.Version, record.Version, StringComparison.Ordinal)
            || !string.Equals(verifiedPack.OfficialSource, record.OfficialSource, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Published command pack metadata does not match its immutable JSON snapshot.");
        }

        var lockKey = databasePath + "|publish|" + record.PackId + "|" + record.Version;
        using (var lease = await PublishedCommandPackWriteLock
            .AcquireAsync(lockKey, cancellationToken)
            .ConfigureAwait(false))
        {
            return await RunDatabaseOperationAsync(
                token =>
                {
                    using (var connection = OpenConnection())
                    using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                    using (var command = connection.CreateCommand())
                    {
                        token.ThrowIfCancellationRequested();
                        using (var sourceCommand = connection.CreateCommand())
                        {
                            sourceCommand.Transaction = transaction;
                            sourceCommand.CommandText = "SELECT raw_sha256 FROM command_drafts WHERE id = @sourceDraftId;";
                            sourceCommand.Parameters.AddWithValue("@sourceDraftId", record.SourceDraftId.ToString("D"));
                            var sourceHash = sourceCommand.ExecuteScalar() as string;
                            if (!string.Equals(sourceHash, record.SourceDraftSha256, StringComparison.Ordinal))
                            {
                                throw new InvalidDataException("Published command pack source draft hash does not match the archived draft.");
                            }
                        }

                        command.Transaction = transaction;
                        command.CommandText = "INSERT INTO published_command_packs(pack_id, pack_name, pack_version, official_source, raw_sha256, raw_json, source_draft_id, source_draft_sha256, reviewed_by, reviewed_at_utc, published_at_utc) VALUES(@packId, @packName, @packVersion, @officialSource, @rawSha256, @rawJson, @sourceDraftId, @sourceDraftSha256, @reviewedBy, @reviewedAtUtc, @publishedAtUtc);";
                        AddPublishedCommandPackParameters(command, record);
                        command.ExecuteNonQuery();
                        token.ThrowIfCancellationRequested();
                        transaction.Commit();
                    }

                    return record;
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public Task<PublishedCommandPackRecord?> GetPublishedCommandPackAsync(
        string packId,
        string version,
        CancellationToken cancellationToken = default)
    {
        var normalizedPackId = PublishedCommandPackRecord.RequireText(packId, nameof(packId));
        var normalizedVersion = PublishedCommandPackRecord.RequireText(version, nameof(version));
        return RunDatabaseOperationAsync<PublishedCommandPackRecord?>(
            token =>
            {
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    token.ThrowIfCancellationRequested();
                    command.CommandText = "SELECT pack_id, pack_name, pack_version, official_source, raw_sha256, raw_json, source_draft_id, source_draft_sha256, reviewed_by, reviewed_at_utc, published_at_utc FROM published_command_packs WHERE pack_id = @packId AND pack_version = @packVersion;";
                    command.Parameters.AddWithValue("@packId", normalizedPackId);
                    command.Parameters.AddWithValue("@packVersion", normalizedVersion);
                    using (var reader = command.ExecuteReader())
                    {
                        return reader.Read() ? ReadPublishedCommandPack(reader) : null;
                    }
                }
            },
            cancellationToken);
    }

    public Task<IReadOnlyList<PublishedCommandPackRecord>> GetPublishedCommandPacksAsync(
        CancellationToken cancellationToken = default)
    {
        return RunDatabaseOperationAsync<IReadOnlyList<PublishedCommandPackRecord>>(
            token =>
            {
                var records = new List<PublishedCommandPackRecord>();
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT pack_id, pack_name, pack_version, official_source, raw_sha256, raw_json, source_draft_id, source_draft_sha256, reviewed_by, reviewed_at_utc, published_at_utc FROM published_command_packs ORDER BY published_at_utc DESC, rowid DESC;";
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            token.ThrowIfCancellationRequested();
                            records.Add(ReadPublishedCommandPack(reader));
                        }
                    }
                }

                return records.AsReadOnly();
            },
            cancellationToken);
    }

    public async Task<ProjectCommandPackLockRecord> AppendProjectCommandPackLockAsync(
        ProjectId projectId,
        string packId,
        string version,
        long expectedRevision,
        string lockSource,
        DateTimeOffset lockedAt,
        CancellationToken cancellationToken = default)
    {
        if (expectedRevision < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedRevision));
        }

        var normalizedPackId = PublishedCommandPackRecord.RequireText(packId, nameof(packId));
        var normalizedVersion = PublishedCommandPackRecord.RequireText(version, nameof(version));
        var normalizedSource = PublishedCommandPackRecord.RequireText(lockSource, nameof(lockSource));
        var lockKey = databasePath + "|project-pack|" + projectId + "|" + normalizedPackId;
        using (var lease = await ProjectCommandPackLockWriteLock
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
                        var current = ReadLatestProjectCommandPackLock(
                            connection, transaction, projectId, normalizedPackId);
                        var actualRevision = current?.Revision ?? 0;
                        if (actualRevision != expectedRevision)
                        {
                            throw new DBConcurrencyException(
                                "Project command pack lock revision changed. Expected "
                                + expectedRevision + " but found " + actualRevision + ".");
                        }

                        var record = new ProjectCommandPackLockRecord(
                            Guid.NewGuid(),
                            projectId,
                            normalizedPackId,
                            normalizedVersion,
                            actualRevision + 1,
                            current?.Id,
                            normalizedSource,
                            lockedAt);
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "INSERT INTO project_command_pack_locks(id, project_id, pack_id, pack_version, revision, previous_lock_id, lock_source, locked_at_utc) VALUES(@id, @projectId, @packId, @packVersion, @revision, @previousLockId, @lockSource, @lockedAtUtc);";
                            AddProjectCommandPackLockParameters(command, record);
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

    public Task<ProjectCommandPackLockRecord?> GetCurrentProjectCommandPackLockAsync(
        ProjectId projectId,
        string packId,
        CancellationToken cancellationToken = default)
    {
        var normalizedPackId = PublishedCommandPackRecord.RequireText(packId, nameof(packId));
        return RunDatabaseOperationAsync<ProjectCommandPackLockRecord?>(
            token =>
            {
                token.ThrowIfCancellationRequested();
                using (var connection = OpenConnection())
                {
                    return ReadLatestProjectCommandPackLock(
                        connection, null, projectId, normalizedPackId);
                }
            },
            cancellationToken);
    }

    public Task<IReadOnlyList<ProjectCommandPackLockRecord>> GetCurrentProjectCommandPackLocksAsync(
        ProjectId projectId,
        CancellationToken cancellationToken = default)
    {
        return ReadProjectCommandPackLocksAsync(
            "SELECT l.id, l.project_id, l.pack_id, l.pack_version, l.revision, l.previous_lock_id, l.lock_source, l.locked_at_utc FROM project_command_pack_locks l WHERE l.project_id = @projectId AND NOT EXISTS (SELECT 1 FROM project_command_pack_locks newer WHERE newer.project_id = l.project_id AND newer.pack_id = l.pack_id AND newer.revision > l.revision) ORDER BY l.pack_id;",
            projectId,
            null,
            cancellationToken);
    }

    public Task<IReadOnlyList<ProjectCommandPackLockRecord>> GetProjectCommandPackLockHistoryAsync(
        ProjectId projectId,
        string packId,
        CancellationToken cancellationToken = default)
    {
        var normalizedPackId = PublishedCommandPackRecord.RequireText(packId, nameof(packId));
        return ReadProjectCommandPackLocksAsync(
            "SELECT id, project_id, pack_id, pack_version, revision, previous_lock_id, lock_source, locked_at_utc FROM project_command_pack_locks WHERE project_id = @projectId AND pack_id = @packId ORDER BY revision;",
            projectId,
            normalizedPackId,
            cancellationToken);
    }

    private Task<IReadOnlyList<ProjectCommandPackLockRecord>> ReadProjectCommandPackLocksAsync(
        string sql,
        ProjectId projectId,
        string? packId,
        CancellationToken cancellationToken)
    {
        return RunDatabaseOperationAsync<IReadOnlyList<ProjectCommandPackLockRecord>>(
            token =>
            {
                var records = new List<ProjectCommandPackLockRecord>();
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = sql;
                    command.Parameters.AddWithValue("@projectId", projectId.ToString());
                    if (packId != null)
                    {
                        command.Parameters.AddWithValue("@packId", packId);
                    }

                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            token.ThrowIfCancellationRequested();
                            records.Add(ReadProjectCommandPackLock(reader));
                        }
                    }
                }

                return records.AsReadOnly();
            },
            cancellationToken);
    }

    private static ProjectCommandPackLockRecord? ReadLatestProjectCommandPackLock(
        SQLiteConnection connection,
        SQLiteTransaction? transaction,
        ProjectId projectId,
        string packId)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT id, project_id, pack_id, pack_version, revision, previous_lock_id, lock_source, locked_at_utc FROM project_command_pack_locks WHERE project_id = @projectId AND pack_id = @packId ORDER BY revision DESC LIMIT 1;";
            command.Parameters.AddWithValue("@projectId", projectId.ToString());
            command.Parameters.AddWithValue("@packId", packId);
            using (var reader = command.ExecuteReader())
            {
                return reader.Read() ? ReadProjectCommandPackLock(reader) : null;
            }
        }
    }

    private static PublishedCommandPackRecord ReadPublishedCommandPack(SQLiteDataReader reader)
    {
        return new PublishedCommandPackRecord(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetString(5),
            Guid.Parse(reader.GetString(6)),
            reader.GetString(7),
            reader.GetString(8),
            ParseUtc(reader.GetString(9)),
            ParseUtc(reader.GetString(10)));
    }

    private static ProjectCommandPackLockRecord ReadProjectCommandPackLock(SQLiteDataReader reader)
    {
        return new ProjectCommandPackLockRecord(
            Guid.Parse(reader.GetString(0)),
            ProjectId.Parse(reader.GetString(1)),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetInt64(4),
            reader.IsDBNull(5) ? (Guid?)null : Guid.Parse(reader.GetString(5)),
            reader.GetString(6),
            ParseUtc(reader.GetString(7)));
    }

    private static void AddPublishedCommandPackParameters(
        SQLiteCommand command,
        PublishedCommandPackRecord record)
    {
        command.Parameters.AddWithValue("@packId", record.PackId);
        command.Parameters.AddWithValue("@packName", record.PackName);
        command.Parameters.AddWithValue("@packVersion", record.Version);
        command.Parameters.AddWithValue("@officialSource", record.OfficialSource);
        command.Parameters.AddWithValue("@rawSha256", record.RawSha256);
        command.Parameters.AddWithValue("@rawJson", record.RawJson);
        command.Parameters.AddWithValue("@sourceDraftId", record.SourceDraftId.ToString("D"));
        command.Parameters.AddWithValue("@sourceDraftSha256", record.SourceDraftSha256);
        command.Parameters.AddWithValue("@reviewedBy", record.ReviewedBy);
        command.Parameters.AddWithValue("@reviewedAtUtc", FormatUtc(record.ReviewedAt));
        command.Parameters.AddWithValue("@publishedAtUtc", FormatUtc(record.PublishedAt));
    }

    private static void AddProjectCommandPackLockParameters(
        SQLiteCommand command,
        ProjectCommandPackLockRecord record)
    {
        command.Parameters.AddWithValue("@id", record.Id.ToString("D"));
        command.Parameters.AddWithValue("@projectId", record.ProjectId.ToString());
        command.Parameters.AddWithValue("@packId", record.PackId);
        command.Parameters.AddWithValue("@packVersion", record.Version);
        command.Parameters.AddWithValue("@revision", record.Revision);
        command.Parameters.AddWithValue(
            "@previousLockId",
            record.PreviousLockId.HasValue
                ? (object)record.PreviousLockId.Value.ToString("D")
                : DBNull.Value);
        command.Parameters.AddWithValue("@lockSource", record.LockSource);
        command.Parameters.AddWithValue("@lockedAtUtc", FormatUtc(record.LockedAt));
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
}
