using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.RegularExpressions;
using AssessmentTool.Core.Domain;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AssessmentTool.Core.Detection;

public sealed class HostMiddlewareDiscovery
{
    private const int MaximumLineLength = 65536;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
    private static readonly Regex ProcessShape = Pattern(@"^\s*\d+\s+(?<command>\S+)\s*$");
    private static readonly Regex NginxProcess = Pattern(@"^nginx$");
    private static readonly Regex ApacheProcess = Pattern(@"^(?:apache2|httpd)$");
    private static readonly Regex NginxService = Pattern(@"^(?<name>nginx\.service)\s+loaded\s+active\s+running\s+.+$");
    private static readonly Regex ApacheService = Pattern(@"^(?<name>(?:apache2|httpd)\.service)\s+loaded\s+active\s+running\s+.+$");
    private static readonly Regex TomcatService = Pattern(@"^(?<name>tomcat(?:8|9|10)?\.service)\s+loaded\s+active\s+running\s+.+$");
    private static readonly Regex NumericVersionPrefix = Pattern(@"^(?<version>\d+(?:\.\d+)*)(?:[-_].*)?$");

    private const string ProcessCommandId = "database-host-discovery-linux-processes";
    private const string ServiceCommandId = "database-host-discovery-linux-services";
    private const string DockerCommandId = "database-host-discovery-linux-docker-containers";
    private const string PodmanCommandId = "database-host-discovery-linux-podman-containers";

    public IReadOnlyList<MiddlewareInstanceCandidate> Detect(IReadOnlyList<CommandOutput> outputs)
    {
        if (outputs == null)
        {
            throw new ArgumentNullException(nameof(outputs));
        }

        var local = new List<LocalObservation>();
        var containers = new List<MiddlewareInstanceCandidate>();
        foreach (var output in outputs)
        {
            if (output == null)
            {
                throw new ArgumentException("中间件发现输出不能包含空项。", nameof(outputs));
            }

            if (output.Outcome != RemoteExecutionOutcome.Succeeded)
            {
                continue;
            }

            if (string.Equals(output.CommandId, ProcessCommandId, StringComparison.Ordinal))
            {
                ParseProcesses(output.StandardOutput, local);
            }
            else if (string.Equals(output.CommandId, ServiceCommandId, StringComparison.Ordinal))
            {
                ParseServices(output.StandardOutput, local);
            }
            else if (string.Equals(output.CommandId, DockerCommandId, StringComparison.Ordinal)
                || string.Equals(output.CommandId, PodmanCommandId, StringComparison.Ordinal))
            {
                ParseContainers(output.StandardOutput, containers);
            }
        }

        var candidates = MergeLocal(local)
            .Concat(containers)
            .GroupBy(CandidateIdentity, StringComparer.Ordinal)
            .Select(group => group.First())
            .OrderBy(candidate => candidate.Product, StringComparer.Ordinal)
            .ThenBy(candidate => candidate.InstallationType)
            .ThenBy(candidate => candidate.InstanceName, StringComparer.Ordinal)
            .ToArray();
        return new ReadOnlyCollection<MiddlewareInstanceCandidate>(candidates);
    }

    private static void ParseProcesses(string transcript, ICollection<LocalObservation> observations)
    {
        foreach (var line in ReadSafeLines(transcript))
        {
            var shape = ProcessShape.Match(line);
            if (!shape.Success)
            {
                continue;
            }

            var command = shape.Groups["command"].Value;
            if (NginxProcess.IsMatch(command))
            {
                observations.Add(new LocalObservation("Nginx", command, line.Trim(), false));
            }
            else if (ApacheProcess.IsMatch(command))
            {
                observations.Add(new LocalObservation("Apache HTTP Server", command, line.Trim(), false));
            }
        }
    }

    private static void ParseServices(string transcript, ICollection<LocalObservation> observations)
    {
        foreach (var line in ReadSafeLines(transcript))
        {
            AddService(line, NginxService, "Nginx", observations);
            AddService(line, ApacheService, "Apache HTTP Server", observations);
            AddService(line, TomcatService, "Apache Tomcat", observations);
        }
    }

    private static void AddService(
        string line,
        Regex signature,
        string product,
        ICollection<LocalObservation> observations)
    {
        var match = signature.Match(line);
        if (match.Success)
        {
            observations.Add(new LocalObservation(product, match.Groups["name"].Value, line, true));
        }
    }

    private static IEnumerable<MiddlewareInstanceCandidate> MergeLocal(
        IEnumerable<LocalObservation> observations)
    {
        foreach (var group in observations.GroupBy(item => item.Product, StringComparer.Ordinal))
        {
            var services = group
                .Where(item => item.IsService)
                .GroupBy(item => item.InstanceName, StringComparer.OrdinalIgnoreCase)
                .Select(item => item.First())
                .ToArray();
            var processes = group
                .Where(item => !item.IsService)
                .GroupBy(item => item.InstanceName, StringComparer.OrdinalIgnoreCase)
                .Select(item => item.First())
                .ToArray();
            if (services.Length == 0)
            {
                foreach (var process in processes)
                {
                    yield return new MiddlewareInstanceCandidate(
                        process.Product,
                        null,
                        MiddlewareInstallationType.LocalService,
                        process.InstanceName,
                        null,
                        process.Evidence,
                        0.70);
                }

                continue;
            }

            foreach (var service in services)
            {
                yield return new MiddlewareInstanceCandidate(
                    service.Product,
                    null,
                    MiddlewareInstallationType.LocalService,
                    service.InstanceName,
                    null,
                    services.Length == 1 && processes.Length != 0
                        ? processes[0].Evidence
                        : service.Evidence,
                    services.Length == 1 && processes.Length != 0 ? 0.90 : 0.70);
            }
        }
    }

    private static void ParseContainers(
        string transcript,
        ICollection<MiddlewareInstanceCandidate> candidates)
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
            if (image == null || name == null || !TryParseOfficialImage(image, out var product, out var version))
            {
                continue;
            }

            candidates.Add(new MiddlewareInstanceCandidate(
                product,
                version,
                MiddlewareInstallationType.Container,
                name,
                ports,
                line,
                version == null ? 0.70 : 0.96));
        }
    }

    private static bool TryParseOfficialImage(string image, out string product, out string? version)
    {
        product = string.Empty;
        version = null;
        var withoutDigest = image.Split('@')[0];
        var slashIndex = withoutDigest.LastIndexOf('/');
        var colonIndex = withoutDigest.LastIndexOf(':');
        var hasTag = colonIndex > slashIndex;
        var repository = hasTag ? withoutDigest.Substring(0, colonIndex) : withoutDigest;
        var tag = hasTag ? withoutDigest.Substring(colonIndex + 1) : null;

        if (IsOfficialRepository(repository, "nginx"))
        {
            product = "Nginx";
        }
        else if (IsOfficialRepository(repository, "httpd"))
        {
            product = "Apache HTTP Server";
        }
        else if (IsOfficialRepository(repository, "tomcat"))
        {
            product = "Apache Tomcat";
        }
        else
        {
            return false;
        }

        if (tag != null)
        {
            var match = NumericVersionPrefix.Match(tag);
            if (match.Success)
            {
                version = match.Groups["version"].Value;
            }
        }

        return true;
    }

    private static bool IsOfficialRepository(string repository, string product)
    {
        return string.Equals(repository, product, StringComparison.OrdinalIgnoreCase)
            || string.Equals(repository, "library/" + product, StringComparison.OrdinalIgnoreCase)
            || string.Equals(repository, "docker.io/library/" + product, StringComparison.OrdinalIgnoreCase);
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
            && !value.Any(char.IsControl)
                ? value
                : null;
    }

    private static IEnumerable<string> ReadSafeLines(string transcript)
    {
        if (transcript == null)
        {
            yield break;
        }

        foreach (var line in transcript.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            if (line.Length > 0 && line.Length <= MaximumLineLength && !line.Any(char.IsControl))
            {
                yield return line;
            }
        }
    }

    private static string CandidateIdentity(MiddlewareInstanceCandidate candidate)
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

    private sealed class LocalObservation
    {
        public LocalObservation(string product, string instanceName, string evidence, bool isService)
        {
            Product = product;
            InstanceName = instanceName;
            Evidence = evidence;
            IsService = isService;
        }

        public string Product { get; }
        public string InstanceName { get; }
        public string Evidence { get; }
        public bool IsService { get; }
    }
}
