using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Core.Detection;

public sealed class DetectionEngine
{
    public DetectionResult Detect(string transcript, IReadOnlyList<IdentificationRule> rules)
    {
        if (transcript == null)
        {
            throw new ArgumentNullException(nameof(transcript));
        }

        if (string.IsNullOrWhiteSpace(transcript))
        {
            throw new ArgumentException("Transcript cannot be blank.", nameof(transcript));
        }

        if (rules == null)
        {
            throw new ArgumentNullException(nameof(rules));
        }

        var candidates = new List<DetectionCandidate>();
        try
        {
            foreach (var rule in rules)
            {
                if (rule == null)
                {
                    throw new ArgumentException("Identification rules cannot contain null elements.", nameof(rules));
                }

                candidates.AddRange(rule.FindMatches(transcript));
            }
        }
        catch (RegexMatchTimeoutException)
        {
            return new DetectionResult(Array.Empty<DetectionCandidate>());
        }

        var uniqueCandidates = candidates
            .GroupBy(candidate => candidate, CandidateIdentityComparer.Instance)
            .Select(group => group
                .OrderByDescending(candidate => candidate.Confidence)
                .ThenBy(candidate => candidate.Evidence, StringComparer.Ordinal)
                .ThenBy(candidate => candidate.Vendor, StringComparer.Ordinal)
                .ThenBy(candidate => candidate.ProductFamily, StringComparer.Ordinal)
                .ThenBy(candidate => candidate.Model, StringComparer.Ordinal)
                .ThenBy(candidate => candidate.Version, StringComparer.Ordinal)
                .First())
            .OrderByDescending(candidate => candidate.Confidence)
            .ThenBy(candidate => candidate.Category)
            .ThenBy(candidate => candidate.Vendor, StringComparer.OrdinalIgnoreCase)
            .ThenBy(candidate => candidate.Vendor, StringComparer.Ordinal)
            .ThenBy(candidate => candidate.ProductFamily, StringComparer.OrdinalIgnoreCase)
            .ThenBy(candidate => candidate.ProductFamily, StringComparer.Ordinal)
            .ThenBy(candidate => candidate.Model, StringComparer.OrdinalIgnoreCase)
            .ThenBy(candidate => candidate.Model, StringComparer.Ordinal)
            .ThenBy(candidate => candidate.Version, StringComparer.OrdinalIgnoreCase)
            .ThenBy(candidate => candidate.Version, StringComparer.Ordinal)
            .ThenBy(candidate => candidate.Evidence, StringComparer.Ordinal)
            .ToArray();

        return new DetectionResult(uniqueCandidates);
    }

    private sealed class CandidateIdentityComparer : IEqualityComparer<DetectionCandidate>
    {
        public static readonly CandidateIdentityComparer Instance = new CandidateIdentityComparer();

        public bool Equals(DetectionCandidate? left, DetectionCandidate? right)
        {
            if (ReferenceEquals(left, right))
            {
                return true;
            }

            if (left == null || right == null)
            {
                return false;
            }

            return left.Category == right.Category
                && Equal(left.Vendor, right.Vendor)
                && Equal(left.ProductFamily, right.ProductFamily)
                && Equal(left.Model, right.Model)
                && Equal(left.Version, right.Version);
        }

        public int GetHashCode(DetectionCandidate candidate)
        {
            if (candidate == null)
            {
                return 0;
            }

            unchecked
            {
                var hash = (int)candidate.Category;
                hash = (hash * 397) ^ Hash(candidate.Vendor);
                hash = (hash * 397) ^ Hash(candidate.ProductFamily);
                hash = (hash * 397) ^ Hash(candidate.Model);
                hash = (hash * 397) ^ Hash(candidate.Version);
                return hash;
            }
        }

        private static bool Equal(string? left, string? right)
        {
            return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }

        private static int Hash(string? value)
        {
            return value == null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(value);
        }
    }
}
