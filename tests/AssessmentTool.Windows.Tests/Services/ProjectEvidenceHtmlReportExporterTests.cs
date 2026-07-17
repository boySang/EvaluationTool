using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.App.Services;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class ProjectEvidenceHtmlReportExporterTests
{
    [Fact]
    public async Task Export_creates_encoded_offline_report_without_connection_secrets()
    {
        var project = new ProjectRecord(
            ProjectId.New(),
            "客户<script>alert(1)</script>",
            "项目甲 & 复核",
            @"C:\客户资料\项目甲",
            DateTimeOffset.Parse("2026-07-17T08:00:00Z"));
        var execution = new ExecutionRecord(
            project.Id.ToString(),
            DeviceId.New().ToString(),
            ConnectionProtocol.Ssh,
            "linux@1.0",
            "linux.identity",
            "cat /etc/login.defs <safe>",
            DateTimeOffset.Parse("2026-07-17T09:00:00Z"),
            DateTimeOffset.Parse("2026-07-17T09:00:01Z"),
            ExecutionStatus.Failed,
            1,
            null,
            null,
            Array.Empty<string>(),
            new Dictionary<string, string>(),
            "测试连接失败");
        var document = CreateDocument(project, execution);
        var provider = new FakeDocumentProvider(new ProjectEvidenceManifestDocument(
            project,
            new[] { execution },
            Array.Empty<EvidenceFileRecord>(),
            new EvidenceCenterSnapshot(project.Id, Array.Empty<EvidenceCenterItem>()),
            document,
            0));
        var exporter = new ProjectEvidenceHtmlReportExporter(provider);
        var directory = Path.Combine(Path.GetTempPath(), "EvaluationTool-report-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "项目证据报告.html");
            var result = await exporter.ExportAsync(project, path);
            var html = File.ReadAllText(path);

            Assert.Equal(1, result.ExecutionCount);
            Assert.Contains("Content-Security-Policy", html, StringComparison.Ordinal);
            Assert.Contains("script-src 'none'", html, StringComparison.Ordinal);
            Assert.Contains("客户&lt;script&gt;alert(1)&lt;/script&gt;", html, StringComparison.Ordinal);
            Assert.Contains("cat /etc/login.defs &lt;safe&gt;", html, StringComparison.Ordinal);
            Assert.DoesNotContain("<script>alert(1)</script>", html, StringComparison.Ordinal);
            Assert.DoesNotContain(project.EvidenceRoot, html, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("192.0.2.10", html, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("audit-user", html, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Export_refuses_to_overwrite_existing_report()
    {
        var project = new ProjectRecord(ProjectId.New(), "客户", "项目", @"C:\Evidence", DateTimeOffset.UtcNow);
        var provider = new FakeDocumentProvider(new ProjectEvidenceManifestDocument(
            project,
            Array.Empty<ExecutionRecord>(),
            Array.Empty<EvidenceFileRecord>(),
            new EvidenceCenterSnapshot(project.Id, Array.Empty<EvidenceCenterItem>()),
            CreateDocument(project),
            0));
        var exporter = new ProjectEvidenceHtmlReportExporter(provider);
        var path = Path.Combine(Path.GetTempPath(), "EvaluationTool-existing-" + Guid.NewGuid().ToString("N") + ".html");
        File.WriteAllText(path, "keep");
        try
        {
            await Assert.ThrowsAsync<IOException>(() => exporter.ExportAsync(project, path));
            Assert.Equal("keep", File.ReadAllText(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static JObject CreateDocument(ProjectRecord project, ExecutionRecord? execution = null)
    {
        return new JObject
        {
            ["generatedAtUtc"] = "2026-07-17T10:00:00Z",
            ["exportNotice"] = "不包含密码、主机地址和输出正文。",
            ["verificationMode"] = "已只读复算 SHA-256。",
            ["project"] = new JObject
            {
                ["customerName"] = project.CustomerName,
                ["projectName"] = project.ProjectName
            },
            ["summary"] = new JObject
            {
                ["deviceCount"] = 1,
                ["executionCount"] = execution == null ? 0 : 1,
                ["evidenceFileCount"] = 0,
                ["verifiedExecutionCount"] = 0
            },
            ["devices"] = new JArray(new JObject
            {
                ["displayName"] = "Linux服务器甲",
                ["category"] = "Server",
                ["protocol"] = "Ssh"
            }),
            ["executions"] = execution == null ? new JArray() : new JArray(new JObject
            {
                ["deviceName"] = "Linux服务器甲",
                ["commandId"] = execution.CommandId,
                ["commandText"] = execution.CommandText,
                ["status"] = execution.Status.ToString(),
                ["integrityStatus"] = "NotAvailable",
                ["startedAtUtc"] = execution.StartedAt.ToString("O")
            }),
            ["evidenceFiles"] = new JArray(),
            ["databaseConfirmations"] = new JArray(),
            ["hostSoftwareDiscoveryBatches"] = new JArray()
        };
    }

    private sealed class FakeDocumentProvider : IProjectEvidenceManifestDocumentProvider
    {
        private readonly ProjectEvidenceManifestDocument document;
        internal FakeDocumentProvider(ProjectEvidenceManifestDocument document) => this.document = document;
        public Task<ProjectEvidenceManifestDocument> CreateDocumentAsync(
            ProjectRecord project,
            CancellationToken cancellationToken = default) => Task.FromResult(document);
    }
}
