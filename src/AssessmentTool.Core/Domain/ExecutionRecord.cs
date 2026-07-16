using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace AssessmentTool.Core.Domain;

public enum ExecutionStatus
{
    Pending,
    Running,
    Succeeded,
    Failed,
    Skipped,
    Stopped
}

public sealed class ExecutionRecord
{
    public ExecutionRecord(
        string projectId,
        string deviceId,
        ConnectionProtocol connectionProtocol,
        string commandPackVersion,
        string commandId,
        string commandText,
        DateTimeOffset startedAt,
        DateTimeOffset? completedAt,
        ExecutionStatus status,
        int? exitCode,
        string? rawOutputPath,
        string? rawOutputSha256,
        IEnumerable<string> evidenceImagePaths,
        IDictionary<string, string> evidenceImageSha256s,
        string? errorText)
    {
        ProjectId = projectId ?? throw new ArgumentNullException(nameof(projectId));
        DeviceId = deviceId ?? throw new ArgumentNullException(nameof(deviceId));
        if (!Enum.IsDefined(typeof(ConnectionProtocol), connectionProtocol))
        {
            throw new ArgumentOutOfRangeException(nameof(connectionProtocol), connectionProtocol, "Connection protocol is invalid.");
        }

        if (!Enum.IsDefined(typeof(ExecutionStatus), status))
        {
            throw new ArgumentOutOfRangeException(nameof(status), status, "Execution status is invalid.");
        }

        ConnectionProtocol = connectionProtocol;
        CommandPackVersion = commandPackVersion ?? throw new ArgumentNullException(nameof(commandPackVersion));
        CommandId = commandId ?? throw new ArgumentNullException(nameof(commandId));
        CommandText = commandText ?? throw new ArgumentNullException(nameof(commandText));
        StartedAt = startedAt;
        CompletedAt = completedAt;
        Status = status;
        ExitCode = exitCode;
        if (evidenceImagePaths == null)
        {
            throw new ArgumentNullException(nameof(evidenceImagePaths));
        }

        if (evidenceImageSha256s == null)
        {
            throw new ArgumentNullException(nameof(evidenceImageSha256s));
        }

        var copiedEvidenceImagePaths = new List<string>();
        var evidenceImagePathSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var evidenceImagePath in evidenceImagePaths)
        {
            var normalizedEvidenceImagePath = WindowsEvidenceRelativePathPolicy.Normalize(
                evidenceImagePath,
                nameof(evidenceImagePaths));
            if (!evidenceImagePathSet.Add(normalizedEvidenceImagePath))
            {
                throw new ArgumentException(
                    "Evidence image paths must be unique after Windows path normalization.",
                    nameof(evidenceImagePaths));
            }

            copiedEvidenceImagePaths.Add(normalizedEvidenceImagePath);
        }

        var copiedEvidenceImageSha256s = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var evidenceImageSha256 in evidenceImageSha256s)
        {
            var normalizedEvidenceHashPath = WindowsEvidenceRelativePathPolicy.Normalize(
                evidenceImageSha256.Key,
                nameof(evidenceImageSha256s));
            if (!evidenceImagePathSet.Contains(normalizedEvidenceHashPath)
                || !IsValidSha256(evidenceImageSha256.Value)
                || copiedEvidenceImageSha256s.ContainsKey(normalizedEvidenceHashPath))
            {
                throw new ArgumentException(
                    "Evidence image hashes must use normalized supplied paths and valid SHA-256 values.",
                    nameof(evidenceImageSha256s));
            }

            copiedEvidenceImageSha256s.Add(normalizedEvidenceHashPath, evidenceImageSha256.Value);
        }

        if (copiedEvidenceImageSha256s.Count != copiedEvidenceImagePaths.Count)
        {
            throw new ArgumentException(
                "Every evidence image path requires exactly one SHA-256 hash using ordinal-ignore-case path matching.",
                nameof(evidenceImageSha256s));
        }

        string? normalizedRawOutputPath = null;
        if (rawOutputPath == null)
        {
            if (rawOutputSha256 != null)
            {
                throw new ArgumentException("Raw output hash cannot be supplied without a raw output path.", nameof(rawOutputSha256));
            }
        }
        else
        {
            normalizedRawOutputPath = WindowsEvidenceRelativePathPolicy.Normalize(rawOutputPath, nameof(rawOutputPath));
            if (!IsValidSha256(rawOutputSha256))
            {
                throw new ArgumentException("Every raw output path requires a valid SHA-256 hash.", nameof(rawOutputSha256));
            }
        }

        if (status == ExecutionStatus.Succeeded)
        {
            if (normalizedRawOutputPath == null)
            {
                throw new ArgumentException("Succeeded records require a raw output path.", nameof(rawOutputPath));
            }

            if (copiedEvidenceImagePaths.Count == 0)
            {
                throw new ArgumentException(
                    "Succeeded records require one valid SHA-256 hash for every evidence image path.",
                    nameof(evidenceImageSha256s));
            }
        }

        EvidenceImagePaths = copiedEvidenceImagePaths.AsReadOnly();
        EvidenceImageSha256s = new ReadOnlyDictionary<string, string>(copiedEvidenceImageSha256s);
        RawOutputPath = normalizedRawOutputPath;
        RawOutputSha256 = rawOutputSha256;
        ErrorText = errorText;
    }

    public string ProjectId { get; }
    public string DeviceId { get; }
    public ConnectionProtocol ConnectionProtocol { get; }
    public string CommandPackVersion { get; }
    public string CommandId { get; }
    public string CommandText { get; }
    public DateTimeOffset StartedAt { get; }
    public DateTimeOffset? CompletedAt { get; }
    public ExecutionStatus Status { get; }
    public int? ExitCode { get; }
    public string? RawOutputPath { get; }
    public string? RawOutputSha256 { get; }
    public IReadOnlyList<string> EvidenceImagePaths { get; }
    public IReadOnlyDictionary<string, string> EvidenceImageSha256s { get; }
    public string? ErrorText { get; }

    private static bool IsValidSha256(string? value)
    {
        if (value == null || value.Length != 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            var isDecimalDigit = character >= '0' && character <= '9';
            var isLowercaseHexLetter = character >= 'a' && character <= 'f';
            var isUppercaseHexLetter = character >= 'A' && character <= 'F';
            if (!isDecimalDigit && !isLowercaseHexLetter && !isUppercaseHexLetter)
            {
                return false;
            }
        }

        return true;
    }
}
