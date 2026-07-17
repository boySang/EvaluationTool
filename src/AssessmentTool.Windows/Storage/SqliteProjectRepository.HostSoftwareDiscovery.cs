using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Windows.Storage;

public sealed partial class SqliteProjectRepository
{
    private static readonly KeyedAsyncLock HostSoftwareDiscoveryWriteLock =
        new KeyedAsyncLock(StringComparer.OrdinalIgnoreCase);
    private static readonly KeyedAsyncLock HostSoftwareDecisionWriteLock =
        new KeyedAsyncLock(StringComparer.OrdinalIgnoreCase);

    internal static int HostSoftwareDiscoveryWriteLockCount => HostSoftwareDiscoveryWriteLock.Count;
    internal static int HostSoftwareDecisionWriteLockCount => HostSoftwareDecisionWriteLock.Count;

    public async Task<HostSoftwareDiscoveryBatchRecord> AppendHostSoftwareDiscoveryBatchAsync(
        ProjectId projectId,
        DeviceId deviceId,
        CollectionTaskId collectionTaskId,
        IReadOnlyList<HostSoftwareDiscoveryCandidateInput> candidates,
        string discoverySource,
        DateTimeOffset recordedAt,
        CancellationToken cancellationToken = default)
    {
        if (projectId.Equals(default(ProjectId)))
        {
            throw new ArgumentException("Project ID must be initialized.", nameof(projectId));
        }

        if (deviceId.Equals(default(DeviceId)))
        {
            throw new ArgumentException("Device ID must be initialized.", nameof(deviceId));
        }

        if (collectionTaskId.Equals(default(CollectionTaskId)))
        {
            throw new ArgumentException("Collection task ID must be initialized.", nameof(collectionTaskId));
        }

        if (candidates == null)
        {
            throw new ArgumentNullException(nameof(candidates));
        }

        var copiedCandidates = candidates.ToArray();
        if (copiedCandidates.Length == 0 || copiedCandidates.Length > 64
            || copiedCandidates.Any(candidate => candidate == null))
        {
            throw new ArgumentException("Discovery batch must contain 1 to 64 complete candidates.", nameof(candidates));
        }

        var normalizedSource = HostSoftwareDiscoveryEvidenceInput.RequireText(
            discoverySource, nameof(discoverySource));
        if (recordedAt == default(DateTimeOffset))
        {
            throw new ArgumentException("Discovery time cannot be empty.", nameof(recordedAt));
        }

        var lockKey = databasePath + "|host-software|" + deviceId;
        using (var lease = await HostSoftwareDiscoveryWriteLock
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
                        GetEvidenceRootForDevice(connection, transaction, projectId, deviceId);
                        ValidateHostSoftwareCollectionTask(
                            connection,
                            transaction,
                            projectId,
                            deviceId,
                            collectionTaskId,
                            recordedAt.ToUniversalTime());

                        long revision;
                        Guid? previousBatchId;
                        DateTimeOffset? previousRecordedAt;
                        using (var command = connection.CreateCommand())
                        {
                            command.Transaction = transaction;
                            command.CommandText = "SELECT batch_id, revision, recorded_at_utc FROM host_software_discovery_batches WHERE device_id = @deviceId ORDER BY revision DESC LIMIT 1;";
                            command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                            using (var reader = command.ExecuteReader())
                            {
                                if (reader.Read())
                                {
                                    previousBatchId = Guid.Parse(reader.GetString(0));
                                    revision = checked(reader.GetInt64(1) + 1L);
                                    previousRecordedAt = ParseUtc(reader.GetString(2));
                                }
                                else
                                {
                                    previousBatchId = null;
                                    revision = 1;
                                    previousRecordedAt = null;
                                }
                            }
                        }

                        if (previousRecordedAt.HasValue
                            && recordedAt.ToUniversalTime() < previousRecordedAt.Value)
                        {
                            throw new InvalidOperationException(
                                "A newer host software discovery batch cannot precede the previous batch.");
                        }

                        var batchId = Guid.NewGuid();
                        var candidateRecords = copiedCandidates
                            .Select((candidate, ordinal) => CreateHostSoftwareCandidateRecord(
                                connection,
                                transaction,
                                batchId,
                                collectionTaskId,
                                recordedAt.ToUniversalTime(),
                                ordinal,
                                candidate))
                            .ToArray();
                        var batch = new HostSoftwareDiscoveryBatchRecord(
                            batchId,
                            projectId,
                            deviceId,
                            collectionTaskId,
                            revision,
                            previousBatchId,
                            normalizedSource,
                            candidateRecords,
                            recordedAt);

                        InsertHostSoftwareBatch(connection, transaction, batch);
                        foreach (var candidate in batch.Candidates)
                        {
                            InsertHostSoftwareCandidate(connection, transaction, candidate);
                            foreach (var source in candidate.Sources)
                            {
                                InsertHostSoftwareEvidence(connection, transaction, source);
                            }
                        }

                        if (previousBatchId.HasValue)
                        {
                            SupersedePendingHostSoftwareCandidates(
                                connection,
                                transaction,
                                previousBatchId.Value,
                                batch.BatchId,
                                batch.RecordedAt,
                                token);
                        }

                        token.ThrowIfCancellationRequested();
                        transaction.Commit();
                        return batch;
                    }
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public Task<HostSoftwareDiscoveryBatchRecord?> GetLatestHostSoftwareDiscoveryBatchAsync(
        DeviceId deviceId,
        CancellationToken cancellationToken = default)
    {
        if (deviceId.Equals(default(DeviceId)))
        {
            throw new ArgumentException("Device ID must be initialized.", nameof(deviceId));
        }

        return RunDatabaseOperationAsync<HostSoftwareDiscoveryBatchRecord?>(
            token =>
            {
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    token.ThrowIfCancellationRequested();
                    command.CommandText = "SELECT batch_id FROM host_software_discovery_batches WHERE device_id = @deviceId ORDER BY revision DESC LIMIT 1;";
                    command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                    var batchId = command.ExecuteScalar() as string;
                    return batchId == null
                        ? null
                        : ReadHostSoftwareBatch(connection, Guid.Parse(batchId), token);
                }
            },
            cancellationToken);
    }

    public Task<IReadOnlyList<HostSoftwareDiscoveryBatchRecord>> GetHostSoftwareDiscoveryHistoryAsync(
        DeviceId deviceId,
        CancellationToken cancellationToken = default)
    {
        if (deviceId.Equals(default(DeviceId)))
        {
            throw new ArgumentException("Device ID must be initialized.", nameof(deviceId));
        }

        return RunDatabaseOperationAsync<IReadOnlyList<HostSoftwareDiscoveryBatchRecord>>(
            token =>
            {
                var batchIds = new List<Guid>();
                var batches = new List<HostSoftwareDiscoveryBatchRecord>();
                using (var connection = OpenConnection())
                {
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT batch_id FROM host_software_discovery_batches WHERE device_id = @deviceId ORDER BY revision;";
                        command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                token.ThrowIfCancellationRequested();
                                batchIds.Add(Guid.Parse(reader.GetString(0)));
                            }
                        }
                    }

                    foreach (var batchId in batchIds)
                    {
                        token.ThrowIfCancellationRequested();
                        batches.Add(ReadHostSoftwareBatch(connection, batchId, token));
                    }
                }

                return batches.AsReadOnly();
            },
            cancellationToken);
    }

    public Task<PendingHostSoftwareDiscoveryBatchRecord?> GetLatestPendingHostSoftwareDiscoveryBatchAsync(
        DeviceId deviceId,
        CancellationToken cancellationToken = default)
    {
        if (deviceId.Equals(default(DeviceId)))
        {
            throw new ArgumentException("Device ID must be initialized.", nameof(deviceId));
        }

        return RunDatabaseOperationAsync<PendingHostSoftwareDiscoveryBatchRecord?>(
            token =>
            {
                using (var connection = OpenConnection())
                using (var transaction = connection.BeginTransaction(IsolationLevel.Serializable))
                {
                    token.ThrowIfCancellationRequested();
                    Guid? batchId;
                    using (var command = connection.CreateCommand())
                    {
                        command.Transaction = transaction;
                        command.CommandText = "SELECT batch_id FROM host_software_discovery_batches WHERE device_id = @deviceId ORDER BY revision DESC LIMIT 1;";
                        command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
                        var storedBatchId = command.ExecuteScalar() as string;
                        batchId = storedBatchId == null ? (Guid?)null : Guid.Parse(storedBatchId);
                    }

                    if (!batchId.HasValue)
                    {
                        transaction.Commit();
                        return null;
                    }

                    var batch = ReadHostSoftwareBatch(
                        connection, batchId.Value, token, transaction);
                    var pendingCandidateIds = new HashSet<Guid>();
                    using (var command = connection.CreateCommand())
                    {
                        command.Transaction = transaction;
                        command.CommandText = "SELECT c.candidate_id FROM host_software_discovery_candidates c LEFT JOIN host_software_candidate_decisions d ON d.candidate_id = c.candidate_id WHERE c.batch_id = @batchId AND d.decision_id IS NULL ORDER BY c.ordinal;";
                        command.Parameters.AddWithValue("@batchId", batchId.Value.ToString("D"));
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                token.ThrowIfCancellationRequested();
                                pendingCandidateIds.Add(Guid.Parse(reader.GetString(0)));
                            }
                        }
                    }

                    if (pendingCandidateIds.Count == 0)
                    {
                        transaction.Commit();
                        return null;
                    }

                    var pendingCandidates = batch.Candidates
                        .Where(candidate => pendingCandidateIds.Contains(candidate.CandidateId))
                        .ToArray();
                    if (pendingCandidates.Length != pendingCandidateIds.Count)
                    {
                        throw new InvalidDataException(
                            "Pending host software discovery candidates are incomplete.");
                    }

                    var result = new PendingHostSoftwareDiscoveryBatchRecord(batch, pendingCandidates);
                    transaction.Commit();
                    return result;
                }
            },
            cancellationToken);
    }

    public async Task<HostSoftwareCandidateDecisionRecord> AppendHostSoftwareCandidateDecisionAsync(
        Guid candidateId,
        HostSoftwareCandidateDecision decision,
        string decidedBy,
        string decisionSource,
        string? reason,
        DateTimeOffset decidedAt,
        CancellationToken cancellationToken = default)
    {
        if (decision == HostSoftwareCandidateDecision.Superseded)
        {
            throw new ArgumentOutOfRangeException(
                nameof(decision),
                decision,
                "Superseded decisions are reserved for transactional replacement by a newer batch.");
        }

        var record = new HostSoftwareCandidateDecisionRecord(
            Guid.NewGuid(), candidateId, decision, decidedBy, decisionSource, reason, decidedAt);
        var lockKey = databasePath + "|host-software-decision|" + candidateId.ToString("D");
        using (var lease = await HostSoftwareDecisionWriteLock
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
                        command.Transaction = transaction;
                        command.CommandText = "INSERT INTO host_software_candidate_decisions(decision_id, candidate_id, decision, decided_by, decision_source, reason, decided_at_utc) SELECT @decisionId, c.candidate_id, @decision, @decidedBy, @decisionSource, @reason, @decidedAtUtc FROM host_software_discovery_candidates c INNER JOIN host_software_discovery_batches b ON b.batch_id = c.batch_id WHERE c.candidate_id = @candidateId AND @decidedAtUtc >= b.recorded_at_utc AND NOT EXISTS (SELECT 1 FROM host_software_candidate_decisions d WHERE d.candidate_id = c.candidate_id);";
                        AddHostSoftwareDecisionParameters(command, record);
                        if (command.ExecuteNonQuery() != 1)
                        {
                            throw new InvalidOperationException(
                                "Host software candidate does not exist or already has an immutable decision.");
                        }

                        token.ThrowIfCancellationRequested();
                        transaction.Commit();
                        return record;
                    }
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public Task<IReadOnlyList<HostSoftwareCandidateDecisionRecord>> GetHostSoftwareCandidateDecisionsAsync(
        Guid batchId,
        CancellationToken cancellationToken = default)
    {
        HostSoftwareDiscoveryEvidenceRecord.RequireId(batchId, nameof(batchId));
        return RunDatabaseOperationAsync<IReadOnlyList<HostSoftwareCandidateDecisionRecord>>(
            token =>
            {
                var records = new List<HostSoftwareCandidateDecisionRecord>();
                using (var connection = OpenConnection())
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT d.decision_id, d.candidate_id, d.decision, d.decided_by, d.decision_source, d.reason, d.decided_at_utc FROM host_software_candidate_decisions d INNER JOIN host_software_discovery_candidates c ON c.candidate_id = d.candidate_id WHERE c.batch_id = @batchId ORDER BY c.ordinal;";
                    command.Parameters.AddWithValue("@batchId", batchId.ToString("D"));
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            token.ThrowIfCancellationRequested();
                            records.Add(ReadHostSoftwareDecision(reader));
                        }
                    }
                }

                return records.AsReadOnly();
            },
            cancellationToken);
    }

    private static HostSoftwareDiscoveryCandidateRecord CreateHostSoftwareCandidateRecord(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        Guid batchId,
        CollectionTaskId collectionTaskId,
        DateTimeOffset recordedAt,
        int ordinal,
        HostSoftwareDiscoveryCandidateInput candidate)
    {
        var candidateId = Guid.NewGuid();
        var sources = candidate.Sources
            .Select((source, sourceOrdinal) => ResolveHostSoftwareEvidenceRecord(
                connection,
                transaction,
                candidateId,
                collectionTaskId,
                recordedAt,
                sourceOrdinal,
                source))
            .ToArray();
        return new HostSoftwareDiscoveryCandidateRecord(
            candidateId,
            batchId,
            ordinal,
            candidate.Category,
            candidate.Product,
            candidate.Version,
            candidate.InstallationType,
            candidate.InstanceName,
            candidate.PortEvidence,
            candidate.Confidence,
            sources);
    }

    private static HostSoftwareDiscoveryEvidenceRecord ResolveHostSoftwareEvidenceRecord(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        Guid candidateId,
        CollectionTaskId collectionTaskId,
        DateTimeOffset recordedAt,
        int sourceOrdinal,
        HostSoftwareDiscoveryEvidenceInput source)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT c.ordinal FROM collection_task_commands c WHERE c.task_id = @taskId AND c.command_id = @commandId AND EXISTS (SELECT 1 FROM collection_task_events e WHERE e.task_id = c.task_id AND e.command_ordinal = c.ordinal AND e.event_code = 'CommandEvidenceCommitted' AND e.occurred_at_utc <= @recordedAtUtc);";
            command.Parameters.AddWithValue("@taskId", collectionTaskId.ToString());
            command.Parameters.AddWithValue("@commandId", source.SourceCommandId);
            command.Parameters.AddWithValue("@recordedAtUtc", FormatUtc(recordedAt));
            var storedOrdinal = command.ExecuteScalar();
            if (storedOrdinal == null || storedOrdinal == DBNull.Value)
            {
                throw new InvalidOperationException(
                    "Host software evidence command was not committed by the associated collection task.");
            }

            return new HostSoftwareDiscoveryEvidenceRecord(
                Guid.NewGuid(),
                candidateId,
                sourceOrdinal,
                collectionTaskId,
                Convert.ToInt32(storedOrdinal),
                source.Kind,
                source.SourceCommandId,
                source.Excerpt,
                source.RawOutputSha256);
        }
    }

    private static void ValidateHostSoftwareCollectionTask(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        ProjectId projectId,
        DeviceId deviceId,
        CollectionTaskId collectionTaskId,
        DateTimeOffset recordedAt)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT COUNT(*) FROM collection_tasks WHERE id = @taskId AND project_id = @projectId AND device_id = @deviceId AND created_at_utc <= @recordedAtUtc;";
            command.Parameters.AddWithValue("@taskId", collectionTaskId.ToString());
            command.Parameters.AddWithValue("@projectId", projectId.ToString());
            command.Parameters.AddWithValue("@deviceId", deviceId.ToString());
            command.Parameters.AddWithValue("@recordedAtUtc", FormatUtc(recordedAt));
            if (Convert.ToInt32(command.ExecuteScalar()) != 1)
            {
                throw new InvalidOperationException(
                    "Collection task does not belong to the host software discovery project and device.");
            }
        }
    }

    private static void InsertHostSoftwareBatch(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        HostSoftwareDiscoveryBatchRecord batch)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO host_software_discovery_batches(batch_id, project_id, device_id, collection_task_id, revision, previous_batch_id, discovery_source, candidate_count, recorded_at_utc) VALUES(@batchId, @projectId, @deviceId, @collectionTaskId, @revision, @previousBatchId, @discoverySource, @candidateCount, @recordedAtUtc);";
            command.Parameters.AddWithValue("@batchId", batch.BatchId.ToString("D"));
            command.Parameters.AddWithValue("@projectId", batch.ProjectId.ToString());
            command.Parameters.AddWithValue("@deviceId", batch.DeviceId.ToString());
            command.Parameters.AddWithValue("@collectionTaskId", batch.CollectionTaskId.ToString());
            command.Parameters.AddWithValue("@revision", batch.Revision);
            command.Parameters.AddWithValue("@previousBatchId", batch.PreviousBatchId.HasValue
                ? (object)batch.PreviousBatchId.Value.ToString("D")
                : DBNull.Value);
            command.Parameters.AddWithValue("@discoverySource", batch.DiscoverySource);
            command.Parameters.AddWithValue("@candidateCount", batch.Candidates.Count);
            command.Parameters.AddWithValue("@recordedAtUtc", FormatUtc(batch.RecordedAt));
            command.ExecuteNonQuery();
        }
    }

    private static void InsertHostSoftwareCandidate(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        HostSoftwareDiscoveryCandidateRecord candidate)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO host_software_discovery_candidates(candidate_id, batch_id, ordinal, category, product, version, installation_type, instance_name, port_evidence, confidence, evidence_count) VALUES(@candidateId, @batchId, @ordinal, @category, @product, @version, @installationType, @instanceName, @portEvidence, @confidence, @evidenceCount);";
            command.Parameters.AddWithValue("@candidateId", candidate.CandidateId.ToString("D"));
            command.Parameters.AddWithValue("@batchId", candidate.BatchId.ToString("D"));
            command.Parameters.AddWithValue("@ordinal", candidate.Ordinal);
            command.Parameters.AddWithValue("@category", (int)candidate.Category);
            command.Parameters.AddWithValue("@product", candidate.Product);
            command.Parameters.AddWithValue("@version", (object?)candidate.Version ?? DBNull.Value);
            command.Parameters.AddWithValue("@installationType", (int)candidate.InstallationType);
            command.Parameters.AddWithValue("@instanceName", candidate.InstanceName);
            command.Parameters.AddWithValue("@portEvidence", (object?)candidate.PortEvidence ?? DBNull.Value);
            command.Parameters.AddWithValue("@confidence", candidate.Confidence);
            command.Parameters.AddWithValue("@evidenceCount", candidate.Sources.Count);
            command.ExecuteNonQuery();
        }
    }

    private static void InsertHostSoftwareEvidence(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        HostSoftwareDiscoveryEvidenceRecord source)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO host_software_discovery_evidence(evidence_id, candidate_id, ordinal, collection_task_id, command_ordinal, evidence_kind, source_command_id, evidence_excerpt, raw_output_sha256) VALUES(@evidenceId, @candidateId, @ordinal, @collectionTaskId, @commandOrdinal, @evidenceKind, @sourceCommandId, @evidenceExcerpt, @rawOutputSha256);";
            command.Parameters.AddWithValue("@evidenceId", source.EvidenceId.ToString("D"));
            command.Parameters.AddWithValue("@candidateId", source.CandidateId.ToString("D"));
            command.Parameters.AddWithValue("@ordinal", source.Ordinal);
            command.Parameters.AddWithValue("@collectionTaskId", source.CollectionTaskId.ToString());
            command.Parameters.AddWithValue("@commandOrdinal", source.CommandOrdinal);
            command.Parameters.AddWithValue("@evidenceKind", (int)source.Kind);
            command.Parameters.AddWithValue("@sourceCommandId", source.SourceCommandId);
            command.Parameters.AddWithValue("@evidenceExcerpt", source.Excerpt);
            command.Parameters.AddWithValue("@rawOutputSha256", source.RawOutputSha256);
            command.ExecuteNonQuery();
        }
    }

    private static void AddHostSoftwareDecisionParameters(
        SQLiteCommand command,
        HostSoftwareCandidateDecisionRecord record)
    {
        command.Parameters.AddWithValue("@decisionId", record.DecisionId.ToString("D"));
        command.Parameters.AddWithValue("@candidateId", record.CandidateId.ToString("D"));
        command.Parameters.AddWithValue("@decision", (int)record.Decision);
        command.Parameters.AddWithValue("@decidedBy", record.DecidedBy);
        command.Parameters.AddWithValue("@decisionSource", record.DecisionSource);
        command.Parameters.AddWithValue("@reason", (object?)record.Reason ?? DBNull.Value);
        command.Parameters.AddWithValue("@decidedAtUtc", FormatUtc(record.DecidedAt));
    }

    private static void SupersedePendingHostSoftwareCandidates(
        SQLiteConnection connection,
        SQLiteTransaction transaction,
        Guid previousBatchId,
        Guid replacementBatchId,
        DateTimeOffset replacementRecordedAt,
        CancellationToken cancellationToken)
    {
        var candidateIds = new List<Guid>();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT c.candidate_id FROM host_software_discovery_candidates c LEFT JOIN host_software_candidate_decisions d ON d.candidate_id = c.candidate_id WHERE c.batch_id = @batchId AND d.decision_id IS NULL ORDER BY c.ordinal;";
            command.Parameters.AddWithValue("@batchId", previousBatchId.ToString("D"));
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    candidateIds.Add(Guid.Parse(reader.GetString(0)));
                }
            }
        }

        foreach (var candidateId in candidateIds)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var record = new HostSoftwareCandidateDecisionRecord(
                Guid.NewGuid(),
                candidateId,
                HostSoftwareCandidateDecision.Superseded,
                "system",
                "new-host-software-discovery-batch:" + replacementBatchId.ToString("D"),
                "Superseded by newer host software discovery batch "
                    + replacementBatchId.ToString("D") + ".",
                replacementRecordedAt);
            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = "INSERT INTO host_software_candidate_decisions(decision_id, candidate_id, decision, decided_by, decision_source, reason, decided_at_utc) VALUES(@decisionId, @candidateId, @decision, @decidedBy, @decisionSource, @reason, @decidedAtUtc);";
                AddHostSoftwareDecisionParameters(command, record);
                command.ExecuteNonQuery();
            }
        }
    }

    private static HostSoftwareDiscoveryBatchRecord ReadHostSoftwareBatch(
        SQLiteConnection connection,
        Guid batchId,
        CancellationToken cancellationToken,
        SQLiteTransaction? transaction = null)
    {
        ProjectId projectId;
        DeviceId deviceId;
        CollectionTaskId collectionTaskId;
        long revision;
        Guid? previousBatchId;
        string discoverySource;
        int candidateCount;
        DateTimeOffset recordedAt;
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT project_id, device_id, collection_task_id, revision, previous_batch_id, discovery_source, candidate_count, recorded_at_utc FROM host_software_discovery_batches WHERE batch_id = @batchId;";
            command.Parameters.AddWithValue("@batchId", batchId.ToString("D"));
            using (var reader = command.ExecuteReader())
            {
                if (!reader.Read())
                {
                    throw new InvalidOperationException("Host software discovery batch was not found.");
                }

                projectId = ProjectId.Parse(reader.GetString(0));
                deviceId = DeviceId.Parse(reader.GetString(1));
                collectionTaskId = CollectionTaskId.Parse(reader.GetString(2));
                revision = reader.GetInt64(3);
                previousBatchId = reader.IsDBNull(4) ? (Guid?)null : Guid.Parse(reader.GetString(4));
                discoverySource = reader.GetString(5);
                candidateCount = reader.GetInt32(6);
                recordedAt = ParseUtc(reader.GetString(7));
            }
        }

        var storedCandidates = new List<StoredHostSoftwareCandidate>();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT candidate_id, ordinal, category, product, version, installation_type, instance_name, port_evidence, confidence, evidence_count FROM host_software_discovery_candidates WHERE batch_id = @batchId ORDER BY ordinal;";
            command.Parameters.AddWithValue("@batchId", batchId.ToString("D"));
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    storedCandidates.Add(new StoredHostSoftwareCandidate(
                        Guid.Parse(reader.GetString(0)),
                        reader.GetInt32(1),
                        HostSoftwareDiscoveryEvidenceInput.RequireEnum(
                            (HostSoftwareCategory)reader.GetInt32(2), "stored category"),
                        reader.GetString(3),
                        ReadNullableString(reader, 4),
                        HostSoftwareDiscoveryEvidenceInput.RequireEnum(
                            (HostSoftwareInstallationType)reader.GetInt32(5), "stored installation type"),
                        reader.GetString(6),
                        ReadNullableString(reader, 7),
                        reader.GetDouble(8),
                        reader.GetInt32(9)));
                }
            }
        }

        var candidates = new List<HostSoftwareDiscoveryCandidateRecord>();
        foreach (var storedCandidate in storedCandidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sources = ReadHostSoftwareEvidence(
                connection, storedCandidate.CandidateId, cancellationToken, transaction);
            if (sources.Count != storedCandidate.EvidenceCount)
            {
                throw new InvalidDataException("Host software discovery evidence is incomplete.");
            }

            candidates.Add(new HostSoftwareDiscoveryCandidateRecord(
                storedCandidate.CandidateId,
                batchId,
                storedCandidate.Ordinal,
                storedCandidate.Category,
                storedCandidate.Product,
                storedCandidate.Version,
                storedCandidate.InstallationType,
                storedCandidate.InstanceName,
                storedCandidate.PortEvidence,
                storedCandidate.Confidence,
                sources));
        }

        if (candidates.Count != candidateCount)
        {
            throw new InvalidDataException("Host software discovery candidate batch is incomplete.");
        }

        return new HostSoftwareDiscoveryBatchRecord(
            batchId,
            projectId,
            deviceId,
            collectionTaskId,
            revision,
            previousBatchId,
            discoverySource,
            candidates,
            recordedAt);
    }

    private static IReadOnlyList<HostSoftwareDiscoveryEvidenceRecord> ReadHostSoftwareEvidence(
        SQLiteConnection connection,
        Guid candidateId,
        CancellationToken cancellationToken,
        SQLiteTransaction? transaction = null)
    {
        var sources = new List<HostSoftwareDiscoveryEvidenceRecord>();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT evidence_id, ordinal, collection_task_id, command_ordinal, evidence_kind, source_command_id, evidence_excerpt, raw_output_sha256 FROM host_software_discovery_evidence WHERE candidate_id = @candidateId ORDER BY ordinal;";
            command.Parameters.AddWithValue("@candidateId", candidateId.ToString("D"));
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    sources.Add(new HostSoftwareDiscoveryEvidenceRecord(
                        Guid.Parse(reader.GetString(0)),
                        candidateId,
                        reader.GetInt32(1),
                        CollectionTaskId.Parse(reader.GetString(2)),
                        reader.GetInt32(3),
                        HostSoftwareDiscoveryEvidenceInput.RequireEnum(
                            (HostSoftwareEvidenceKind)reader.GetInt32(4), "stored evidence kind"),
                        reader.GetString(5),
                        reader.GetString(6),
                        reader.GetString(7)));
                }
            }
        }

        return sources.AsReadOnly();
    }

    private static HostSoftwareCandidateDecisionRecord ReadHostSoftwareDecision(SQLiteDataReader reader)
    {
        return new HostSoftwareCandidateDecisionRecord(
            Guid.Parse(reader.GetString(0)),
            Guid.Parse(reader.GetString(1)),
            HostSoftwareDiscoveryEvidenceInput.RequireEnum(
                (HostSoftwareCandidateDecision)reader.GetInt32(2), "stored decision"),
            reader.GetString(3),
            reader.GetString(4),
            ReadNullableString(reader, 5),
            ParseUtc(reader.GetString(6)));
    }

    private sealed class StoredHostSoftwareCandidate
    {
        public StoredHostSoftwareCandidate(
            Guid candidateId,
            int ordinal,
            HostSoftwareCategory category,
            string product,
            string? version,
            HostSoftwareInstallationType installationType,
            string instanceName,
            string? portEvidence,
            double confidence,
            int evidenceCount)
        {
            CandidateId = candidateId;
            Ordinal = ordinal;
            Category = category;
            Product = product;
            Version = version;
            InstallationType = installationType;
            InstanceName = instanceName;
            PortEvidence = portEvidence;
            Confidence = confidence;
            EvidenceCount = evidenceCount;
        }

        public Guid CandidateId { get; }
        public int Ordinal { get; }
        public HostSoftwareCategory Category { get; }
        public string Product { get; }
        public string? Version { get; }
        public HostSoftwareInstallationType InstallationType { get; }
        public string InstanceName { get; }
        public string? PortEvidence { get; }
        public double Confidence { get; }
        public int EvidenceCount { get; }
    }
}
