using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.App.Services;

public interface ICollectionEvidenceService
{
    Task<SavedCollectionEvidence> SaveAsync(
        ProjectRecord project,
        DeviceRecord device,
        string commandPackVersion,
        CommandDefinition command,
        CommandOutput output,
        CancellationToken cancellationToken = default);
}

public sealed class SavedCollectionEvidence
{
    public SavedCollectionEvidence(
        string batchDirectory,
        string manifestPath,
        ExecutionRecord execution,
        IReadOnlyList<string> evidenceImagePaths,
        bool isIndexed)
    {
        BatchDirectory = Required(batchDirectory, nameof(batchDirectory));
        ManifestPath = Required(manifestPath, nameof(manifestPath));
        Execution = execution ?? throw new ArgumentNullException(nameof(execution));
        if (evidenceImagePaths == null)
        {
            throw new ArgumentNullException(nameof(evidenceImagePaths));
        }

        EvidenceImagePaths = new ReadOnlyCollection<string>(evidenceImagePaths.ToArray());
        IsIndexed = isIndexed;
    }

    public string BatchDirectory { get; }
    public string ManifestPath { get; }
    public ExecutionRecord Execution { get; }
    public IReadOnlyList<string> EvidenceImagePaths { get; }
    public bool IsIndexed { get; }

    private static string Required(string value, string parameterName)
    {
        return string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("证据路径不能为空。", parameterName)
            : value;
    }
}

public sealed class CollectionEvidenceException : InvalidOperationException
{
    public CollectionEvidenceException(string message, SavedCollectionEvidence savedEvidence, Exception innerException)
        : base(message, innerException)
    {
        SavedEvidence = savedEvidence ?? throw new ArgumentNullException(nameof(savedEvidence));
    }

    public SavedCollectionEvidence SavedEvidence { get; }
}
