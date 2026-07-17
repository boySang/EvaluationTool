using System;
using System.Collections.Generic;
using System.Linq;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Core.Detection;

internal sealed class LinuxOsReleaseVersionEnricher
{
    private const int MaximumLineLength = 4096;

    public DetectionResult Enrich(string transcript, DetectionResult detection)
    {
        if (transcript == null)
        {
            throw new ArgumentNullException(nameof(transcript));
        }

        if (detection == null)
        {
            throw new ArgumentNullException(nameof(detection));
        }

        if (detection.WasUserConfirmed
            || !TryReadSingleValue(transcript, "ID", out var operatingSystemId)
            || !TryReadSingleValue(transcript, "VERSION_ID", out var version)
            || !Version.TryParse(version, out _))
        {
            return detection;
        }

        var changed = false;
        var candidates = detection.Candidates.Select(candidate =>
        {
            if (candidate.Category != TargetCategory.Server
                || candidate.Version != null
                || !string.Equals(candidate.Vendor, operatingSystemId, StringComparison.OrdinalIgnoreCase))
            {
                return candidate;
            }

            changed = true;
            return new DetectionCandidate(
                candidate.Category,
                candidate.Vendor,
                candidate.ProductFamily,
                candidate.Model,
                version,
                candidate.Evidence + "\nVERSION_ID=" + version,
                candidate.Confidence);
        }).ToArray();

        return changed ? new DetectionResult(candidates) : detection;
    }

    private static bool TryReadSingleValue(string transcript, string key, out string value)
    {
        var values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in ReadLines(transcript))
        {
            if (line.Length > MaximumLineLength
                || !line.StartsWith(key + "=", StringComparison.Ordinal))
            {
                continue;
            }

            if (!TryNormalizeValue(line.Substring(key.Length + 1), out var normalized))
            {
                value = string.Empty;
                return false;
            }

            values.Add(normalized);
        }

        if (values.Count != 1)
        {
            value = string.Empty;
            return false;
        }

        value = values.Single();
        return true;
    }

    private static bool TryNormalizeValue(string raw, out string value)
    {
        value = raw;
        if (value.Length >= 2 && value[0] == '"' && value[value.Length - 1] == '"')
        {
            value = value.Substring(1, value.Length - 2);
        }
        else if (value.IndexOf('"') >= 0)
        {
            return false;
        }

        if (value.Length == 0 || value.Length > 100 || value.Any(character =>
                !(char.IsLetterOrDigit(character)
                  || character == '.'
                  || character == '_'
                  || character == '+'
                  || character == '-')))
        {
            value = string.Empty;
            return false;
        }

        return true;
    }

    private static IEnumerable<string> ReadLines(string transcript)
    {
        var start = 0;
        for (var index = 0; index < transcript.Length; index++)
        {
            if (transcript[index] != '\r' && transcript[index] != '\n')
            {
                continue;
            }

            yield return transcript.Substring(start, index - start);
            if (transcript[index] == '\r'
                && index + 1 < transcript.Length
                && transcript[index + 1] == '\n')
            {
                index++;
            }

            start = index + 1;
        }

        yield return transcript.Substring(start);
    }
}
