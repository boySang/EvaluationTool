using System;
using System.Collections.Generic;
using System.Linq;

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
        : this(candidates, wasUserConfirmed: false)
    {
    }

    private DetectionResult(IEnumerable<DetectionCandidate> candidates, bool wasUserConfirmed)
    {
        if (candidates == null)
        {
            throw new ArgumentNullException(nameof(candidates));
        }

        var copiedCandidates = new List<DetectionCandidate>(candidates);
        Candidates = copiedCandidates.AsReadOnly();
        WasUserConfirmed = wasUserConfirmed;
        RequiresUserConfirmation = !wasUserConfirmed && (copiedCandidates.Count != 1
            || copiedCandidates[0].Confidence < 0.9
            || copiedCandidates[0].Category == TargetCategory.Automatic);
    }

    public IReadOnlyList<DetectionCandidate> Candidates { get; }
    public bool RequiresUserConfirmation { get; }
    public bool WasUserConfirmed { get; }

    public DetectionResult Confirm(DetectionCandidate selectedCandidate)
    {
        if (selectedCandidate == null)
        {
            throw new ArgumentNullException(nameof(selectedCandidate));
        }

        if (selectedCandidate.Category == TargetCategory.Automatic)
        {
            throw new ArgumentException("人工确认结果必须选择具体对象类别。", nameof(selectedCandidate));
        }

        var currentCandidate = Candidates.FirstOrDefault(candidate =>
            IsSameCandidate(candidate, selectedCandidate));
        if (currentCandidate == null)
        {
            throw new ArgumentException("人工确认结果不属于本次识别候选，已阻止继续执行。", nameof(selectedCandidate));
        }

        return new DetectionResult(new[] { currentCandidate }, wasUserConfirmed: true);
    }

    private static bool IsSameCandidate(DetectionCandidate left, DetectionCandidate right)
    {
        return left.Category == right.Category
            && string.Equals(left.Vendor, right.Vendor, StringComparison.Ordinal)
            && string.Equals(left.ProductFamily, right.ProductFamily, StringComparison.Ordinal)
            && string.Equals(left.Model, right.Model, StringComparison.Ordinal)
            && string.Equals(left.Version, right.Version, StringComparison.Ordinal)
            && string.Equals(left.Evidence, right.Evidence, StringComparison.Ordinal)
            && left.Confidence.Equals(right.Confidence);
    }
}
