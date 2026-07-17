using System;
using System.Collections.Generic;
using System.Linq;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.Core.Commands;

public sealed class CommandMatcher
{
    public IReadOnlyList<CommandDefinition> Match(CommandPack pack, DetectionResult detection)
    {
        if (pack == null)
        {
            throw new ArgumentNullException(nameof(pack));
        }

        if (detection == null)
        {
            throw new ArgumentNullException(nameof(detection));
        }

        if (detection.RequiresUserConfirmation)
        {
            return Array.Empty<CommandDefinition>();
        }

        var target = detection.Candidates[0];

        var candidates = pack.Commands
            .Select((command, index) => new { Command = command, Index = index, Score = Score(command, target) })
            .Where(item => item.Score >= 0)
            .ToArray();

        var selectedAlternativeCommands = candidates
            .Where(item => item.Command.AlternativeGroup != null)
            .GroupBy(item => item.Command.AlternativeGroup!, StringComparer.OrdinalIgnoreCase)
            .Select(group => group
                .OrderByDescending(item => item.Score)
                .ThenBy(item => item.Index)
                .First())
            .ToArray();

        return candidates
            .Where(item => item.Command.AlternativeGroup == null)
            .Concat(selectedAlternativeCommands)
            .OrderByDescending(item => item.Score)
            .ThenBy(item => item.Index)
            .Select(item => item.Command)
            .ToArray();
    }

    private static int Score(CommandDefinition command, DetectionCandidate target)
    {
        if (command.TargetCategory != target.Category
            || !MatchesOptionalText(command.Vendor, target.Vendor)
            || !MatchesOptionalText(command.ProductFamily, target.ProductFamily)
            || !TryScoreModelRange(command.ModelRange, target.Model, out var modelScore))
        {
            return -1;
        }

        var score = 100 + modelScore;
        if (command.Vendor != null)
        {
            score += 10;
        }

        if (command.ProductFamily != null)
        {
            score += 20;
        }

        if (command.MinimumVersion != null || command.MaximumVersion != null)
        {
            if (!Version.TryParse(target.Version, out var targetVersion)
                || (command.MinimumVersion != null && Version.Parse(command.MinimumVersion).CompareTo(targetVersion) > 0)
                || (command.MaximumVersion != null && Version.Parse(command.MaximumVersion).CompareTo(targetVersion) < 0))
            {
                return -1;
            }

            score += 40;
        }

        return score;
    }

    private static bool TryScoreModelRange(string modelRange, string? targetModel, out int score)
    {
        if (modelRange == "*")
        {
            score = 0;
            return true;
        }

        if (targetModel == null)
        {
            score = 0;
            return false;
        }

        if (modelRange.EndsWith("*", StringComparison.Ordinal))
        {
            score = 500;
            return targetModel.StartsWith(
                modelRange.Substring(0, modelRange.Length - 1),
                StringComparison.OrdinalIgnoreCase);
        }

        score = 1000;
        return string.Equals(modelRange, targetModel, StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesOptionalText(string? commandValue, string? targetValue)
    {
        return commandValue == null
            || (targetValue != null && string.Equals(commandValue, targetValue, StringComparison.OrdinalIgnoreCase));
    }
}
