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
    private readonly string? fixedVendor;
    private readonly string? fixedProductFamily;

    private IdentificationRule(
        TargetCategory category,
        string pattern,
        double confidence,
        string verifiedSource,
        string? fixedVendor = null,
        string? fixedProductFamily = null)
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

        if (!expression.GetGroupNames().Contains("vendor", StringComparer.Ordinal)
            && string.IsNullOrWhiteSpace(fixedVendor))
        {
            throw new ArgumentException(
                "Identification pattern must capture the vendor or provide a fixed verified vendor.",
                nameof(pattern));
        }

        Category = category;
        Pattern = pattern;
        Confidence = confidence;
        VerificationStatus = VerificationStatus.Verified;
        VerifiedSource = verifiedSource;
        this.fixedVendor = NormalizeFixedIdentity(fixedVendor, nameof(fixedVendor));
        this.fixedProductFamily = NormalizeFixedIdentity(fixedProductFamily, nameof(fixedProductFamily));
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

    internal static IdentificationRule CreateVerifiedWithFixedIdentity(
        TargetCategory category,
        string pattern,
        double confidence,
        string verifiedSource,
        string vendor,
        string productFamily)
    {
        if (verifiedSource == null)
        {
            throw new ArgumentNullException(nameof(verifiedSource));
        }

        if (string.IsNullOrWhiteSpace(verifiedSource))
        {
            throw new ArgumentException("Verified source cannot be blank.", nameof(verifiedSource));
        }

        return new IdentificationRule(
            category,
            pattern,
            confidence,
            verifiedSource,
            vendor,
            productFamily);
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
                fixedVendor ?? Capture(match, "vendor"),
                fixedProductFamily ?? Capture(match, "productFamily"),
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

    private static string? NormalizeFixedIdentity(string? value, string parameterName)
    {
        if (value == null)
        {
            return null;
        }

        var normalized = value.Trim();
        if (normalized.Length == 0)
        {
            throw new ArgumentException("Fixed identification values cannot be blank.", parameterName);
        }

        return normalized;
    }
}
