using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.RegularExpressions;
using AssessmentTool.Core.Domain;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AssessmentTool.Core.Detection;

public sealed class HostDatabaseDiscovery
{
    private const int MaximumLineLength = 65536;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
    private static readonly Regex ProcessShape = Pattern(@"^\s*\d+\s+(?<command>\S+)\s*$");
    private static readonly Regex PostgreSqlProcess = Pattern(@"^postgres(?:ql)?(?:[-_](?<version>\d+(?:\.\d+)*))?$");
    private static readonly Regex MySqlProcess = Pattern(@"^mysqld(?:[-_](?<version>\d+(?:\.\d+)*))?$");
    private static readonly Regex MariaDbProcess = Pattern(@"^mariadbd(?:[-_](?<version>\d+(?:\.\d+)*))?$");
    private static readonly Regex PostgreSqlService = Pattern(@"^(?<name>postgresql(?:@(?<version>\d+(?:\.\d+)*(?:-[A-Za-z0-9_-]+)?))?\.service)\s+loaded\s+active\s+running\s+.+$");
    private static readonly Regex MySqlService = Pattern(@"^(?<name>mysql\.service)\s+loaded\s+active\s+running\s+MySQL(?:\s+(?<version>\d+(?:\.\d+)*))?(?:\s+Community\s+Server)?$");
    private static readonly Regex MariaDbService = Pattern(@"^(?<name>mariadb\.service)\s+loaded\s+active\s+running\s+MariaDB(?:\s+(?<version>\d+(?:\.\d+)*))?(?:\s+database\s+server)?$");

    private const string ProcessCommandId = "database-host-discovery-linux-processes";
    private const string ServiceCommandId = "database-host-discovery-linux-services";
    private const string DockerCommandId = "database-host-discovery-linux-docker-containers";
    private const string PodmanCommandId = "database-host-discovery-linux-podman-containers";

    public IReadOnlyList<DatabaseInstanceCandidate> Detect(IReadOnlyList<CommandOutput> outputs)
    {
        if (outputs == null)
        {
            throw new ArgumentNullException(nameof(outputs));
        }

        var processes = new List<Observation>();
        var services = new List<Observation>();
        var containers = new List<DatabaseInstanceCandidate>();
        foreach (var output in outputs)
        {
            if (output == null)
            {
                throw new ArgumentException("数据库发现输出不能包含空项。", nameof(outputs));
            }

            if (output.Outcome != RemoteExecutionOutcome.Succeeded)
            {
                continue;
            }

            if (string.Equals(output.CommandId, ProcessCommandId, StringComparison.Ordinal))
            {
                ParseProcesses(output.StandardOutput, processes);
            }
            else if (string.Equals(output.CommandId, ServiceCommandId, StringComparison.Ordinal))
            {
                ParseServices(output.StandardOutput, services);
            }
            else if (string.Equals(output.CommandId, DockerCommandId, StringComparison.Ordinal)
                || string.Equals(output.CommandId, PodmanCommandId, StringComparison.Ordinal))
            {
                ParseContainers(output.StandardOutput, containers);
            }
        }

        var candidates = MergeLocal(processes, services)
            .Concat(containers)
            .GroupBy(CandidateIdentity, StringComparer.Ordinal)
            .Select(group => group.First())
            .OrderBy(candidate => candidate.Product, StringComparer.Ordinal)
            .ThenBy(candidate => candidate.InstallationType)
            .ThenBy(candidate => candidate.InstanceName, StringComparer.Ordinal)
            .ToList();

        var productCounts = candidates
            .GroupBy(candidate => candidate.Product, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.Ordinal);
        for (var index = 0; index < candidates.Count; index++)
        {
            if (productCounts[candidates[index].Product] > 1)
            {
                candidates[index] = candidates[index].RequireConfirmation();
            }
        }

        return new ReadOnlyCollection<DatabaseInstanceCandidate>(candidates);
    }

    private static void ParseProcesses(string transcript, ICollection<Observation> observations)
    {
        foreach (var line in ReadSafeLines(transcript))
        {
            var shape = ProcessShape.Match(line);
            if (!shape.Success)
            {
                continue;
            }

            var command = shape.Groups["command"].Value;
            var evidence = line.Trim();
            AddProcessObservation(evidence, command, PostgreSqlProcess, "PostgreSQL", observations);
            AddProcessObservation(evidence, command, MySqlProcess, "MySQL", observations);
            AddProcessObservation(evidence, command, MariaDbProcess, "MariaDB", observations);
        }
    }

    private static void AddProcessObservation(
        string evidence,
        string command,
        Regex signature,
        string product,
        ICollection<Observation> observations)
    {
        var match = signature.Match(command);
        if (match.Success)
        {
            observations.Add(new Observation(
                product,
                CaptureVersion(match),
                command,
                evidence));
        }
    }

    private static void ParseServices(string transcript, ICollection<Observation> observations)
    {
        foreach (var line in ReadSafeLines(transcript))
        {
            AddServiceObservation(line, PostgreSqlService, "PostgreSQL", observations);
            AddServiceObservation(line, MySqlService, "MySQL", observations);
            AddServiceObservation(line, MariaDbService, "MariaDB", observations);
        }
    }

    private static void AddServiceObservation(
        string evidence,
        Regex signature,
        string product,
        ICollection<Observation> observations)
    {
        var match = signature.Match(evidence);
        if (match.Success)
        {
            var version = CaptureVersion(match);
            if (product == "PostgreSQL" && version != null)
            {
                version = version.Split('-')[0];
            }

            observations.Add(new Observation(
                product,
                version,
                match.Groups["name"].Value,
                evidence));
        }
    }

    private static void ParseContainers(string transcript, ICollection<DatabaseInstanceCandidate> candidates)
    {
        foreach (var line in ReadSafeLines(transcript))
        {
            JObject document;
            try
            {
                using (var reader = new JsonTextReader(new System.IO.StringReader(line)))
                {
                    document = JObject.Load(reader, new JsonLoadSettings
                    {
                        DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error
                    });

                    if (reader.Read())
                    {
                        continue;
                    }
                }
            }
            catch (JsonException)
            {
                continue;
            }

            var propertyNames = document.Properties().Select(property => property.Name).ToArray();
            if (propertyNames.Length != 3
                || !propertyNames.Contains("Image", StringComparer.Ordinal)
                || !propertyNames.Contains("Names", StringComparer.Ordinal)
                || !propertyNames.Contains("Ports", StringComparer.Ordinal))
            {
                continue;
            }

            var image = SafeJsonString(document, "Image", 2048);
            var name = SafeJsonString(document, "Names", 256);
            var ports = SafeJsonString(document, "Ports", 2048);
            if (image == null || name == null || !TryParseImage(image, out var product, out var version))
            {
                continue;
            }

            candidates.Add(new DatabaseInstanceCandidate(
                product,
                version,
                DatabaseInstallationType.Container,
                name,
                ports,
                line,
                version == null ? 0.70 : 0.98,
                requiresUserConfirmation: version == null));
        }
    }

    private static IEnumerable<DatabaseInstanceCandidate> MergeLocal(
        IReadOnlyList<Observation> processes,
        IReadOnlyList<Observation> services)
    {
        foreach (var productGroup in processes.Concat(services).GroupBy(item => item.Product, StringComparer.Ordinal))
        {
            var productProcesses = processes
                .Where(item => item.Product == productGroup.Key)
                .ToList();
            var productServices = services.Where(item => item.Product == productGroup.Key).ToArray();
            if (productServices.Length == 0)
            {
                foreach (var process in productProcesses)
                {
                    yield return LocalCandidate(process, process.InstanceName, process.Evidence, requiresConfirmation: process.Version == null);
                }

                continue;
            }

            foreach (var service in productServices)
            {
                var process = productProcesses.FirstOrDefault(item =>
                    item.Version == null
                    || service.Version == null
                    || string.Equals(item.Version, service.Version, StringComparison.Ordinal));
                if (process != null)
                {
                    productProcesses.Remove(process);
                }

                var version = MergeVersion(process?.Version, service.Version, out var conflict);
                yield return new DatabaseInstanceCandidate(
                    service.Product,
                    version,
                    DatabaseInstallationType.LocalService,
                    service.InstanceName,
                    null,
                    process?.Evidence ?? service.Evidence,
                    version == null ? 0.72 : 0.97,
                    requiresUserConfirmation: conflict || version == null || productServices.Length > 1);
            }

            foreach (var process in productProcesses)
            {
                yield return LocalCandidate(
                    process,
                    process.InstanceName,
                    process.Evidence,
                    requiresConfirmation: true);
            }
        }
    }

    private static DatabaseInstanceCandidate LocalCandidate(
        Observation observation,
        string instanceName,
        string evidence,
        bool requiresConfirmation)
    {
        return new DatabaseInstanceCandidate(
            observation.Product,
            observation.Version,
            DatabaseInstallationType.LocalService,
            instanceName,
            null,
            evidence,
            observation.Version == null ? 0.70 : 0.93,
            requiresConfirmation);
    }

    private static string? MergeVersion(string? first, string? second, out bool conflict)
    {
        conflict = first != null && second != null && !string.Equals(first, second, StringComparison.Ordinal);
        if (conflict)
        {
            return null;
        }

        return first ?? second;
    }

    private static string? SafeJsonString(JObject document, string propertyName, int maximumLength)
    {
        var token = document[propertyName];
        if (token == null || token.Type != JTokenType.String)
        {
            return null;
        }

        var value = token.Value<string>();
        return value != null
            && value.Length <= maximumLength
            && !string.IsNullOrWhiteSpace(value)
            && !ContainsControl(value)
                ? value
                : null;
    }

    private static bool TryParseImage(string image, out string product, out string? version)
    {
        product = string.Empty;
        version = null;
        var segment = image.Substring(image.LastIndexOf('/') + 1);
        var digestIndex = segment.IndexOf('@');
        if (digestIndex >= 0)
        {
            segment = segment.Substring(0, digestIndex);
        }

        var tagIndex = segment.LastIndexOf(':');
        var repository = tagIndex < 0 ? segment : segment.Substring(0, tagIndex);
        var tag = tagIndex < 0 ? null : segment.Substring(tagIndex + 1);
        if (string.Equals(repository, "postgres", StringComparison.OrdinalIgnoreCase))
        {
            product = "PostgreSQL";
        }
        else if (string.Equals(repository, "mysql", StringComparison.OrdinalIgnoreCase))
        {
            product = "MySQL";
        }
        else if (string.Equals(repository, "mariadb", StringComparison.OrdinalIgnoreCase))
        {
            product = "MariaDB";
        }
        else
        {
            return false;
        }

        if (tag != null && Regex.IsMatch(tag, @"^\d+(?:\.\d+)*$", RegexOptions.CultureInvariant, RegexTimeout))
        {
            version = tag;
        }

        return true;
    }

    private static IEnumerable<string> ReadSafeLines(string transcript)
    {
        if (transcript == null)
        {
            yield break;
        }

        foreach (var line in transcript.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            if (line.Length > 0 && line.Length <= MaximumLineLength && !ContainsControl(line))
            {
                yield return line;
            }
        }
    }

    private static bool ContainsControl(string value)
    {
        return value.Any(char.IsControl);
    }

    private static string? CaptureVersion(Match match)
    {
        var group = match.Groups["version"];
        return group.Success && group.Length > 0 ? group.Value : null;
    }

    private static string CandidateIdentity(DatabaseInstanceCandidate candidate)
    {
        return candidate.Product + "\0"
            + candidate.InstallationType + "\0"
            + candidate.InstanceName + "\0"
            + candidate.Version + "\0"
            + candidate.PortEvidence;
    }

    private static Regex Pattern(string pattern)
    {
        return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    }

    private sealed class Observation
    {
        public Observation(string product, string? version, string instanceName, string evidence)
        {
            Product = product;
            Version = version;
            InstanceName = instanceName;
            Evidence = evidence;
        }

        public string Product { get; }
        public string? Version { get; }
        public string InstanceName { get; }
        public string Evidence { get; }
    }
}
