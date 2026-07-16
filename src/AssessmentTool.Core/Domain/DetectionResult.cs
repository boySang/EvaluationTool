using System;
using System.Collections.Generic;

namespace AssessmentTool.Core.Domain;

public sealed class DetectionCandidate
{
    public DetectionCandidate(
        TargetCategory category,
        string? vendor,
        string? productFamily,
        string? model,
        string? version,
        string evidence,
        double confidence)
    {
        Category = category;
        Vendor = vendor;
        ProductFamily = productFamily;
        Model = model;
        Version = version;
        Evidence = evidence ?? throw new ArgumentNullException(nameof(evidence));
        if (double.IsNaN(confidence) || double.IsInfinity(confidence) || confidence < 0 || confidence > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(confidence), confidence, "Confidence must be finite and between 0 and 1.");
        }

        Confidence = confidence;
    }

    public TargetCategory Category { get; }
    public string? Vendor { get; }
    public string? ProductFamily { get; }
    public string? Model { get; }
    public string? Version { get; }
    public string Evidence { get; }
    public double Confidence { get; }
}

public sealed class DetectionResult
{
    public DetectionResult(IEnumerable<DetectionCandidate> candidates)
    {
        if (candidates == null)
        {
            throw new ArgumentNullException(nameof(candidates));
        }

        var copiedCandidates = new List<DetectionCandidate>(candidates);
        Candidates = copiedCandidates.AsReadOnly();
        RequiresUserConfirmation = copiedCandidates.Count != 1
            || copiedCandidates[0].Confidence < 0.9
            || copiedCandidates[0].Category == TargetCategory.Automatic;
    }

    public IReadOnlyList<DetectionCandidate> Candidates { get; }
    public bool RequiresUserConfirmation { get; }
}
