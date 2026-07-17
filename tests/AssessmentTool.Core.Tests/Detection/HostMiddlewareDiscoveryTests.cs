using System;
using System.Collections.Generic;
using System.Linq;
using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Detection;

public sealed class HostMiddlewareDiscoveryTests
{
    private const string ProcessCommandId = "database-host-discovery-linux-processes";
    private const string ServiceCommandId = "database-host-discovery-linux-services";
    private const string DockerCommandId = "database-host-discovery-linux-docker-containers";

    [Fact]
    public void Reuses_existing_outputs_to_detect_supported_local_middleware()
    {
        var outputs = new[]
        {
            Success(ProcessCommandId, "101 nginx\n202 httpd\n303 java"),
            Success(ServiceCommandId, string.Join("\n",
                "nginx.service loaded active running A high performance web server",
                "httpd.service loaded active running Apache HTTP Server",
                "tomcat9.service loaded active running Apache Tomcat"))
        };

        var candidates = new HostMiddlewareDiscovery().Detect(outputs);

        Assert.Equal(3, candidates.Count);
        Assert.Contains(candidates, candidate => candidate.Product == "Nginx");
        Assert.Contains(candidates, candidate => candidate.Product == "Apache HTTP Server");
        Assert.Contains(candidates, candidate => candidate.Product == "Apache Tomcat");
        Assert.Equal("9", Assert.Single(candidates, candidate => candidate.Product == "Apache Tomcat").Version);
        Assert.DoesNotContain(candidates, candidate => candidate.InstanceName == "java");
        Assert.All(candidates, candidate => Assert.True(candidate.RequiresUserConfirmation));
        Assert.All(candidates, candidate => Assert.Equal(MiddlewareInstallationType.LocalService, candidate.InstallationType));
    }

    [Theory]
    [InlineData("nginx:1.27.4", "Nginx", "1.27.4")]
    [InlineData("docker.io/library/httpd:2.4.63", "Apache HTTP Server", "2.4.63")]
    [InlineData("library/tomcat:10.1-jdk17", "Apache Tomcat", "10.1")]
    [InlineData("nginx:latest", "Nginx", null)]
    public void Detects_only_supported_official_container_images(
        string image,
        string product,
        string? version)
    {
        var line = ContainerLine(image, "fixture", "8080/tcp");

        var candidate = Assert.Single(new HostMiddlewareDiscovery().Detect(new[] { Success(DockerCommandId, line) }));

        Assert.Equal(product, candidate.Product);
        Assert.Equal(version, candidate.Version);
        Assert.Equal(MiddlewareInstallationType.Container, candidate.InstallationType);
        Assert.Equal("fixture", candidate.InstanceName);
        Assert.Equal("8080/tcp", candidate.PortEvidence);
        Assert.Equal(line, candidate.Evidence);
        Assert.True(candidate.RequiresUserConfirmation);
    }

    [Theory]
    [InlineData("customer/nginx:1.27")]
    [InlineData("example.com/library/httpd:2.4")]
    [InlineData("tomcat-custom:10.1")]
    public void Similar_non_official_images_are_not_trusted(string image)
    {
        Assert.Empty(new HostMiddlewareDiscovery().Detect(new[]
        {
            Success(DockerCommandId, ContainerLine(image, "untrusted", "8080/tcp"))
        }));
    }

    [Fact]
    public void Inactive_services_java_processes_and_unknown_command_ids_are_ignored()
    {
        var outputs = new[]
        {
            Success(ProcessCommandId, "101 java"),
            Success(ServiceCommandId, "nginx.service loaded inactive dead A high performance web server"),
            Success("legacy-container-list", ContainerLine("nginx:1.27", "legacy", "80/tcp"))
        };

        Assert.Empty(new HostMiddlewareDiscovery().Detect(outputs));
    }

    [Fact]
    public void Multiple_tomcat_services_are_preserved_for_human_confirmation()
    {
        var output = Success(
            ServiceCommandId,
            "tomcat9.service loaded active running Apache Tomcat 9\n"
            + "tomcat10.service loaded active running Apache Tomcat 10");

        var candidates = new HostMiddlewareDiscovery().Detect(new[] { output });

        Assert.Equal(2, candidates.Count);
        Assert.Equal(
            new[] { "tomcat10.service", "tomcat9.service" },
            candidates.Select(candidate => candidate.InstanceName).OrderBy(value => value, StringComparer.Ordinal));
        Assert.Equal(
            new[] { "10", "9" },
            candidates.Select(candidate => candidate.Version).OrderBy(value => value, StringComparer.Ordinal));
        Assert.All(candidates, candidate => Assert.True(candidate.RequiresUserConfirmation));
    }

    [Theory]
    [InlineData("{\"Image\":\"nginx:1.27\",\"Image\":\"httpd:2.4\",\"Names\":\"duplicate\",\"Ports\":\"80/tcp\"}")]
    [InlineData("{\"Image\":\"nginx:1.27\",\"Names\":\"extra\",\"Ports\":\"80/tcp\",\"Command\":\"secret\"}")]
    [InlineData("{\"Image\":\"nginx:1.27\",\"Names\":\"bad\\u0001name\",\"Ports\":\"80/tcp\"}")]
    public void Malformed_or_overbroad_container_metadata_is_ignored(string line)
    {
        Assert.Empty(new HostMiddlewareDiscovery().Detect(new[] { Success(DockerCommandId, line) }));
    }

    [Fact]
    public void Results_are_immutable_snapshots()
    {
        var outputs = new List<CommandOutput>
        {
            Success(DockerCommandId, ContainerLine("nginx:1.27", "fixture", "80/tcp"))
        };

        var results = new HostMiddlewareDiscovery().Detect(outputs);
        outputs.Clear();

        var mutableView = Assert.IsAssignableFrom<IList<MiddlewareInstanceCandidate>>(results);
        Assert.Single(results);
        Assert.Throws<NotSupportedException>(() => mutableView.RemoveAt(0));
        Assert.All(typeof(MiddlewareInstanceCandidate).GetProperties(), property => Assert.Null(property.SetMethod));
    }

    private static CommandOutput Success(string commandId, string standardOutput)
    {
        var timestamp = new DateTimeOffset(2026, 7, 18, 8, 0, 0, TimeSpan.Zero);
        return new CommandOutput(
            commandId,
            standardOutput,
            string.Empty,
            0,
            RemoteExecutionOutcome.Succeeded,
            null,
            timestamp,
            timestamp.AddSeconds(1));
    }

    private static string ContainerLine(string image, string name, string ports)
    {
        return "{\"Image\":\"" + image + "\",\"Names\":\"" + name
            + "\",\"Ports\":\"" + ports + "\"}";
    }
}
