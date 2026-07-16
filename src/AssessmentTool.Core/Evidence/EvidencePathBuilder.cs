using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AssessmentTool.Core.Evidence;

public sealed class EvidencePathBuilder
{
    private const int MaximumSegmentLength = 80;
    private const int MinimumShortenedSegmentLength = 10;
    private static readonly object BatchReservationSync = new object();
    private static readonly HashSet<string> ReservedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CLOCK$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"
    };

    private readonly string rootPath;
    private readonly int maximumTotalPathLength;

    public EvidencePathBuilder(string rootPath, int maximumTotalPathLength = 240)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
        {
            throw new ArgumentException("证据根目录不能为空。", nameof(rootPath));
        }

        if (maximumTotalPathLength < 80)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumTotalPathLength), "证据完整路径上限不能小于 80 个字符。");
        }

        this.rootPath = Path.GetFullPath(rootPath);
        this.maximumTotalPathLength = maximumTotalPathLength;
        if (this.rootPath.Length >= maximumTotalPathLength)
        {
            throw new PathTooLongException("证据根目录本身已经达到完整路径长度上限。");
        }
    }

    public string SanitizeSegment(string input)
    {
        if (input == null)
        {
            throw new ArgumentNullException(nameof(input));
        }

        var characters = input.Select(character => IsInvalid(character) ? '_' : character).ToArray();
        var sanitized = new string(characters).TrimEnd(' ', '.');
        if (string.IsNullOrWhiteSpace(sanitized) || sanitized == "." || sanitized == "..")
        {
            sanitized = "_";
        }

        if (IsReservedName(sanitized))
        {
            sanitized = "_" + sanitized;
        }

        return Shorten(sanitized, MaximumSegmentLength, input);
    }

    public string CreateBatchDirectory(
        string projectName,
        string deviceName,
        string checkItem,
        DateTimeOffset timestamp)
    {
        var originalSegments = new[]
        {
            SanitizeSegment(projectName),
            SanitizeSegment(deviceName),
            SanitizeSegment(checkItem)
        };
        var targetLengths = originalSegments.Select(segment => segment.Length).ToArray();
        const int reservedBatchLength = 24;
        const int reservedArtifactSuffixLength = 48;

        while (BuildLength(originalSegments, targetLengths, reservedBatchLength + reservedArtifactSuffixLength)
            > maximumTotalPathLength)
        {
            var reducible = Enumerable.Range(0, targetLengths.Length)
                .Where(index => targetLengths[index] > MinimumShortenedSegmentLength)
                .OrderByDescending(index => targetLengths[index])
                .DefaultIfEmpty(-1)
                .First();
            if (reducible < 0)
            {
                throw new PathTooLongException("证据目录名称缩短后仍超过 Windows 路径长度上限。");
            }

            targetLengths[reducible]--;
        }

        var segments = originalSegments
            .Select((segment, index) => Shorten(segment, targetLengths[index], segment))
            .ToArray();
        var parent = Path.Combine(rootPath, segments[0], segments[1], segments[2]);
        Directory.CreateDirectory(parent);
        var timestampPart = timestamp.ToUniversalTime().ToString("yyyyMMdd_HHmmss_fff", CultureInfo.InvariantCulture);

        lock (BatchReservationSync)
        {
            for (var ordinal = 1; ordinal <= 9999; ordinal++)
            {
                var candidate = Path.Combine(parent, timestampPart + "-" + ordinal.ToString("000", CultureInfo.InvariantCulture));
                if (candidate.Length + reservedArtifactSuffixLength > maximumTotalPathLength)
                {
                    throw new PathTooLongException("证据批次目录超过 Windows 路径长度上限。");
                }

                var reservationPath = candidate + ".lck";
                FileStream? reservation = null;
                try
                {
                    try
                    {
                        reservation = new FileStream(
                            reservationPath,
                            FileMode.CreateNew,
                            FileAccess.Write,
                            FileShare.None);
                    }
                    catch (IOException)
                    {
                        continue;
                    }

                    if (Directory.Exists(candidate) || File.Exists(candidate))
                    {
                        continue;
                    }

                    Directory.CreateDirectory(candidate);
                    return candidate;
                }
                finally
                {
                    reservation?.Dispose();
                    if (File.Exists(reservationPath))
                    {
                        File.Delete(reservationPath);
                    }
                }
            }
        }

        throw new IOException("同一时间点的证据批次数量超过安全上限。");
    }

    private int BuildLength(string[] segments, int[] targetLengths, int batchLength)
    {
        return rootPath.Length
            + 4
            + targetLengths.Sum()
            + batchLength;
    }

    private static string Shorten(string value, int maximumLength, string hashSource)
    {
        if (value.Length <= maximumLength)
        {
            return value;
        }

        if (maximumLength < MinimumShortenedSegmentLength)
        {
            throw new PathTooLongException("证据目录段没有足够空间保留安全哈希后缀。");
        }

        var hash = ComputeSha256(hashSource).Substring(0, 8);
        return value.Substring(0, maximumLength - 9) + "-" + hash;
    }

    private static bool IsInvalid(char character)
    {
        return character <= '\u001f'
            || character == '<'
            || character == '>'
            || character == ':'
            || character == '"'
            || character == '/'
            || character == '\\'
            || character == '|'
            || character == '?'
            || character == '*'
            || character == '%';
    }

    private static bool IsReservedName(string value)
    {
        var dot = value.IndexOf('.');
        var baseName = dot < 0 ? value : value.Substring(0, dot);
        return ReservedNames.Contains(baseName);
    }

    private static string ComputeSha256(string value)
    {
        using (var sha256 = SHA256.Create())
        {
            var bytes = sha256.ComputeHash(new UTF8Encoding(false, true).GetBytes(value));
            return string.Concat(bytes.Select(item => item.ToString("x2", CultureInfo.InvariantCulture)));
        }
    }
}
