using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Core.Detection;

public sealed class IdentificationRule
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);
    private readonly Regex expression;

    private IdentificationRule(TargetCategory category, string pattern, double confidence, string verifiedSource)
    {
        if (pattern == null)
        {
            throw new ArgumentNullException(nameof(pattern));
        }

        if (string.IsNullOrWhiteSpace(pattern))
        {
            throw new ArgumentException("Identification pattern cannot be blank.", nameof(pattern));
        }

        if (double.IsNaN(confidence) || double.IsInfinity(confidence) || confidence < 0 || confidence > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(confidence), confidence, "Confidence must be finite and between 0 and 1.");
        }

        if (!pattern.StartsWith("^", StringComparison.Ordinal) || !pattern.EndsWith("$", StringComparison.Ordinal))
        {
            throw new ArgumentException("Identification pattern must be anchored with ^ and $.", nameof(pattern));
        }

        try
        {
            expression = new Regex(
                @"\A(?:" + pattern + @")\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                MatchTimeout);
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException("Identification pattern is not a valid regular expression.", nameof(pattern), exception);
        }

        if (!expression.GetGroupNames().Contains("vendor", StringComparer.Ordinal))
        {
            throw new ArgumentException("Identification pattern must capture the vendor in a named 'vendor' group.", nameof(pattern));
        }

        Category = category;
        Pattern = pattern;
        Confidence = confidence;
        VerificationStatus = VerificationStatus.Verified;
        VerifiedSource = verifiedSource;
    }

    public TargetCategory Category { get; }
    public string Pattern { get; }
    public double Confidence { get; }
    public VerificationStatus VerificationStatus { get; }
    public string VerifiedSource { get; }

    internal static IdentificationRule CreateVerified(
        TargetCategory category,
        string pattern,
        double confidence,
        string verifiedSource)
    {
        if (verifiedSource == null)
        {
            throw new ArgumentNullException(nameof(verifiedSource));
        }

        if (string.IsNullOrWhiteSpace(verifiedSource))
        {
            throw new ArgumentException("Verified source cannot be blank.", nameof(verifiedSource));
        }

        return new IdentificationRule(category, pattern, confidence, verifiedSource);
    }

    internal IReadOnlyList<DetectionCandidate> FindMatches(string transcript)
    {
        if (transcript == null)
        {
            throw new ArgumentNullException(nameof(transcript));
        }

        var candidates = new List<DetectionCandidate>();
        foreach (var line in ReadLines(transcript))
        {
            var match = expression.Match(line);
            if (!match.Success)
            {
                continue;
            }

            candidates.Add(new DetectionCandidate(
                Category,
                Capture(match, "vendor"),
                Capture(match, "productFamily"),
                Capture(match, "model"),
                Capture(match, "version"),
                match.Value,
                Confidence));
        }

        return candidates.ToArray();
    }

    private static IEnumerable<string> ReadLines(string transcript)
    {
        var lineStart = 0;
        for (var index = 0; index < transcript.Length; index++)
        {
            if (transcript[index] != '\r' && transcript[index] != '\n')
            {
                continue;
            }

            yield return transcript.Substring(lineStart, index - lineStart);
            if (transcript[index] == '\r' && index + 1 < transcript.Length && transcript[index + 1] == '\n')
            {
                index++;
            }

            lineStart = index + 1;
        }

        yield return transcript.Substring(lineStart);
    }

    private static string? Capture(Match match, string groupName)
    {
        var group = match.Groups[groupName];
        return group.Success && group.Length > 0 ? group.Value : null;
    }
}
