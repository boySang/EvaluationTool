using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using AssessmentTool.Core.Domain;

namespace AssessmentTool.App.Services;

internal sealed class EvidenceFileIntegrityVerifier
{
    internal EvidenceShaStatus Verify(
        string evidenceRoot,
        IEnumerable<ExpectedEvidenceFile> expectedFiles,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(evidenceRoot))
        {
            return EvidenceShaStatus.Unavailable;
        }

        if (expectedFiles == null)
        {
            throw new ArgumentNullException(nameof(expectedFiles));
        }

        var files = expectedFiles.ToArray();
        if (files.Length == 0)
        {
            return EvidenceShaStatus.NotAvailable;
        }

        try
        {
            var normalizedRoot = WindowsEvidenceRootPolicy.Normalize(
                evidenceRoot,
                nameof(evidenceRoot));
            WindowsEvidenceRootPolicy.EnsureNoExistingReparsePoints(normalizedRoot);
            if (!Directory.Exists(normalizedRoot))
            {
                return EvidenceShaStatus.Missing;
            }

            foreach (var expectedFile in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var path = ResolveContainedPath(normalizedRoot, expectedFile.RelativePath);
                if (path == null || ContainsReparsePoint(normalizedRoot, path))
                {
                    return EvidenceShaStatus.UnsafePath;
                }

                if (!File.Exists(path))
                {
                    return EvidenceShaStatus.Missing;
                }

                var actualHash = ComputeSha256(path, cancellationToken);
                if (!string.Equals(actualHash, expectedFile.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    return EvidenceShaStatus.Mismatch;
                }
            }

            return EvidenceShaStatus.Verified;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ArgumentException)
        {
            return EvidenceShaStatus.UnsafePath;
        }
        catch (NotSupportedException)
        {
            return EvidenceShaStatus.UnsafePath;
        }
        catch (PathTooLongException)
        {
            return EvidenceShaStatus.UnsafePath;
        }
        catch (InvalidDataException)
        {
            return EvidenceShaStatus.UnsafePath;
        }
        catch (IOException)
        {
            return EvidenceShaStatus.Unavailable;
        }
        catch (UnauthorizedAccessException)
        {
            return EvidenceShaStatus.Unavailable;
        }
        catch (System.Security.SecurityException)
        {
            return EvidenceShaStatus.Unavailable;
        }
    }

    private static string? ResolveContainedPath(string normalizedRoot, string relativePath)
    {
        return WindowsEvidenceRootPolicy.ResolveContainedPath(
            normalizedRoot,
            relativePath,
            nameof(relativePath));
    }

    private static bool ContainsReparsePoint(string normalizedRoot, string filePath)
    {
        var relativePath = filePath.Substring(normalizedRoot.Length)
            .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var segments = relativePath.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries);
        var current = normalizedRoot;
        foreach (var segment in segments)
        {
            current = Path.Combine(current, segment);
            if ((Directory.Exists(current) || File.Exists(current)) && IsReparsePoint(current))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsReparsePoint(string path)
    {
        return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
    }

    private static string ComputeSha256(string path, CancellationToken cancellationToken)
    {
        using (var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.SequentialScan))
        using (var sha256 = SHA256.Create())
        {
            var buffer = new byte[64 * 1024];
            int bytesRead;
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                sha256.TransformBlock(buffer, 0, bytesRead, buffer, 0);
            }

            sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return string.Concat(sha256.Hash.Select(value => value.ToString("x2", CultureInfo.InvariantCulture)));
        }
    }
}

internal sealed class ExpectedEvidenceFile
{
    internal ExpectedEvidenceFile(string relativePath, string sha256)
    {
        RelativePath = WindowsEvidenceRelativePathPolicy.Normalize(relativePath, nameof(relativePath));
        if (string.IsNullOrWhiteSpace(sha256))
        {
            throw new ArgumentException("证据 SHA-256 不能为空。", nameof(sha256));
        }

        Sha256 = sha256;
    }

    internal string RelativePath { get; }
    internal string Sha256 { get; }
}
