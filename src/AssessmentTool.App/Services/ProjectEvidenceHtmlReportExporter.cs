using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AssessmentTool.Core.Domain;
using AssessmentTool.Windows.Storage;
using Microsoft.Win32;
using Newtonsoft.Json.Linq;

namespace AssessmentTool.App.Services;

public interface IProjectEvidenceHtmlReportExporter
{
    Task<EvidenceHtmlReportExportResult> ExportAsync(
        ProjectRecord project,
        string destinationPath,
        CancellationToken cancellationToken = default);
}

public interface IEvidenceHtmlReportExportFilePicker
{
    string? SelectDestination(ProjectRecord project);
}

public sealed class EvidenceHtmlReportExportResult
{
    public EvidenceHtmlReportExportResult(string path, int executionCount, int evidenceFileCount)
    {
        Path = path ?? throw new ArgumentNullException(nameof(path));
        ExecutionCount = executionCount;
        EvidenceFileCount = evidenceFileCount;
    }

    public string Path { get; }
    public int ExecutionCount { get; }
    public int EvidenceFileCount { get; }
    public string Summary => "已生成包含 " + ExecutionCount + " 条执行记录和 "
        + EvidenceFileCount + " 个证据索引的离线报告。";
}

public sealed class HtmlEvidenceReportExportFilePicker : IEvidenceHtmlReportExportFilePicker
{
    public string? SelectDestination(ProjectRecord project)
    {
        if (project == null)
        {
            throw new ArgumentNullException(nameof(project));
        }

        var dialog = new SaveFileDialog
        {
            Title = "导出项目证据离线报告",
            Filter = "HTML 离线报告 (*.html)|*.html",
            AddExtension = true,
            DefaultExt = ".html",
            FileName = SafeFileName(project.ProjectName) + "-证据报告-"
                + DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + ".html",
            CheckPathExists = true,
            OverwritePrompt = false
        };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    private static string SafeFileName(string value)
    {
        var invalid = new HashSet<char>(Path.GetInvalidFileNameChars());
        var normalized = new string(value.Select(character => invalid.Contains(character) ? '_' : character).ToArray())
            .Trim(' ', '.');
        return string.IsNullOrWhiteSpace(normalized) ? "EvaluationTool" : normalized;
    }
}

public sealed class ProjectEvidenceHtmlReportExporter : IProjectEvidenceHtmlReportExporter
{
    private readonly IProjectEvidenceManifestDocumentProvider documentProvider;

    public ProjectEvidenceHtmlReportExporter(IProjectRepository repository)
        : this(new ProjectEvidenceManifestExporter(repository))
    {
    }

    internal ProjectEvidenceHtmlReportExporter(IProjectEvidenceManifestDocumentProvider documentProvider)
    {
        this.documentProvider = documentProvider ?? throw new ArgumentNullException(nameof(documentProvider));
    }

    public async Task<EvidenceHtmlReportExportResult> ExportAsync(
        ProjectRecord project,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        if (project == null)
        {
            throw new ArgumentNullException(nameof(project));
        }

        var targetPath = LocalExportDestinationPolicy.ValidateNewFile(
            destinationPath,
            ".html",
            nameof(destinationPath));
        var plan = await documentProvider.CreateDocumentAsync(project, cancellationToken).ConfigureAwait(false);
        if (!plan.Project.Id.Equals(project.Id) || !plan.VerifiedSnapshot.ProjectId.Equals(project.Id))
        {
            throw new InvalidDataException("离线报告导出计划属于其他项目。");
        }

        var html = BuildHtml(plan.Document);
        WriteAtomically(targetPath, html, cancellationToken);
        return new EvidenceHtmlReportExportResult(targetPath, plan.Executions.Count, plan.EvidenceFiles.Count);
    }

    private static string BuildHtml(JObject document)
    {
        var project = RequiredObject(document, "project");
        var summary = RequiredObject(document, "summary");
        var devices = RequiredArray(document, "devices");
        var executions = RequiredArray(document, "executions");
        var evidenceFiles = RequiredArray(document, "evidenceFiles");
        var confirmations = RequiredArray(document, "databaseConfirmations");
        var discoveries = RequiredArray(document, "hostSoftwareDiscoveryBatches");
        var builder = new StringBuilder(32 * 1024);
        builder.Append("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
            .Append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'\">")
            .Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>")
            .Append(E(Value(project, "projectName"))).Append(" - 项目证据报告</title><style>")
            .Append("body{margin:0;background:#f5f7fa;color:#172033;font:14px/1.6 'Segoe UI','Microsoft YaHei',sans-serif}.page{max-width:1180px;margin:auto;padding:32px}.hero,.card{background:#fff;border:1px solid #dfe5ec;border-radius:12px;padding:24px;margin-bottom:18px}.hero{border-top:5px solid #1378c8}h1{margin:0 0 8px;font-size:28px}h2{font-size:19px;margin:0 0 14px}.muted{color:#657083}.notice{background:#eef7ff;border-left:4px solid #1378c8;padding:12px 14px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.stat{background:#f7f9fc;border-radius:9px;padding:14px}.stat b{display:block;font-size:24px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #e7ebf0;vertical-align:top;word-break:break-word}th{background:#f7f9fc}.ok{color:#16834a;font-weight:600}.warn{color:#b45309;font-weight:600}.mono{font-family:Consolas,monospace;font-size:12px}@media(max-width:760px){.page{padding:12px}.stats{grid-template-columns:1fr 1fr}.scroll{overflow:auto}}@media print{body{background:#fff}.page{max-width:none;padding:0}.card,.hero{break-inside:avoid;box-shadow:none}}")
            .Append("</style></head><body><main class=\"page\"><section class=\"hero\"><div class=\"muted\">等级保护测评辅助工具 · 只读证据报告</div><h1>")
            .Append(E(Value(project, "projectName"))).Append("</h1><div>客户：")
            .Append(E(Value(project, "customerName"))).Append("</div><div class=\"muted\">生成时间（UTC）：")
            .Append(E(Value(document, "generatedAtUtc"))).Append("</div></section><section class=\"card notice\">")
            .Append(E(Value(document, "exportNotice"))).Append("<br>").Append(E(Value(document, "verificationMode")))
            .Append("<br>本报告仅用于证据复核，不代表自动作出合规结论。</section><section class=\"card\"><h2>项目概览</h2><div class=\"stats\">");
        AppendStat(builder, "设备", Value(summary, "deviceCount"));
        AppendStat(builder, "执行", Value(summary, "executionCount"));
        AppendStat(builder, "证据文件", Value(summary, "evidenceFileCount"));
        AppendStat(builder, "复核通过", Value(summary, "verifiedExecutionCount"));
        builder.Append("</div></section>");
        AppendTable(builder, "设备清单", devices, new[]
        {
            Column("设备名称", "displayName"), Column("类别", "category"), Column("连接方式", "protocol")
        });
        AppendTable(builder, "命令执行与完整性", executions, new[]
        {
            Column("设备", "deviceName"), Column("命令编号", "commandId"), Column("命令", "commandText", true),
            Column("状态", "status"), Column("完整性", "integrityStatus"), Column("开始时间（UTC）", "startedAtUtc")
        });
        AppendTable(builder, "证据文件索引", evidenceFiles, new[]
        {
            Column("设备", "deviceName"), Column("类型", "kind"), Column("相对路径", "relativePath", true),
            Column("SHA-256", "sha256", true)
        });
        AppendTable(builder, "数据库人工确认", confirmations, new[]
        {
            Column("设备", "deviceName"), Column("产品", "product"), Column("版本", "version"),
            Column("实例", "instanceName"), Column("可信度", "confidence"), Column("确认来源", "confirmationSource")
        });
        AppendDiscoverySummary(builder, discoveries);
        builder.Append("<footer class=\"muted\">报告不包含主机地址、用户名、凭据、私钥、令牌或原始输出正文。请与证据包及 JSON 清单一同归档。</footer></main></body></html>");
        return builder.ToString();
    }

    private static void AppendDiscoverySummary(StringBuilder builder, JArray rows)
    {
        builder.Append("<section class=\"card\"><h2>数据库与中间件发现历史</h2><div class=\"scroll\"><table><thead><tr><th>设备</th><th>批次版本</th><th>发现来源</th><th>候选数量</th><th>记录时间（UTC）</th></tr></thead><tbody>");
        foreach (var token in rows.OfType<JObject>())
        {
            builder.Append("<tr><td>").Append(E(Value(token, "deviceName"))).Append("</td><td>")
                .Append(E(Value(token, "revision"))).Append("</td><td>").Append(E(Value(token, "discoverySource")))
                .Append("</td><td>").Append(E((token["candidates"] as JArray)?.Count.ToString(CultureInfo.InvariantCulture) ?? "0"))
                .Append("</td><td>").Append(E(Value(token, "recordedAtUtc"))).Append("</td></tr>");
        }
        if (rows.Count == 0) builder.Append("<tr><td colspan=\"5\" class=\"muted\">暂无记录</td></tr>");
        builder.Append("</tbody></table></div></section>");
    }

    private static void AppendTable(StringBuilder builder, string title, JArray rows, IReadOnlyList<ReportColumn> columns)
    {
        builder.Append("<section class=\"card\"><h2>").Append(E(title)).Append("</h2><div class=\"scroll\"><table><thead><tr>");
        foreach (var column in columns) builder.Append("<th>").Append(E(column.Title)).Append("</th>");
        builder.Append("</tr></thead><tbody>");
        foreach (var row in rows.OfType<JObject>())
        {
            builder.Append("<tr>");
            foreach (var column in columns)
            {
                var value = Value(row, column.Property);
                var css = column.Monospace ? " class=\"mono\"" : string.Equals(value, "Verified", StringComparison.Ordinal) ? " class=\"ok\"" : string.Empty;
                builder.Append("<td").Append(css).Append(">").Append(E(value)).Append("</td>");
            }
            builder.Append("</tr>");
        }
        if (rows.Count == 0) builder.Append("<tr><td colspan=\"").Append(columns.Count).Append("\" class=\"muted\">暂无记录</td></tr>");
        builder.Append("</tbody></table></div></section>");
    }

    private static void AppendStat(StringBuilder builder, string label, string value) => builder
        .Append("<div class=\"stat\"><span>").Append(E(label)).Append("</span><b>").Append(E(value)).Append("</b></div>");
    private static ReportColumn Column(string title, string property, bool monospace = false) => new ReportColumn(title, property, monospace);
    private static JObject RequiredObject(JObject document, string name) => document[name] as JObject ?? throw new InvalidDataException("报告数据缺少 " + name + "。");
    private static JArray RequiredArray(JObject document, string name) => document[name] as JArray ?? throw new InvalidDataException("报告数据缺少 " + name + "。");
    private static string Value(JObject value, string name) => value[name]?.Type == JTokenType.Null ? string.Empty : value[name]?.ToString() ?? string.Empty;
    private static string E(string value) => WebUtility.HtmlEncode(value);

    private static void WriteAtomically(string targetPath, string html, CancellationToken cancellationToken)
    {
        var temporaryPath = targetPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            {
                writer.Write(html);
                writer.Flush();
                stream.Flush(true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            LocalExportDestinationPolicy.RevalidateNewFile(targetPath);
            File.Move(temporaryPath, targetPath);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private sealed class ReportColumn
    {
        internal ReportColumn(string title, string property, bool monospace) { Title = title; Property = property; Monospace = monospace; }
        internal string Title { get; }
        internal string Property { get; }
        internal bool Monospace { get; }
    }
}

internal sealed class UnavailableEvidenceHtmlReportExporter : IProjectEvidenceHtmlReportExporter
{
    public Task<EvidenceHtmlReportExportResult> ExportAsync(ProjectRecord project, string destinationPath, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new InvalidOperationException("项目证据报告导出服务尚未初始化。");
    }
}

internal sealed class UnavailableEvidenceHtmlReportExportFilePicker : IEvidenceHtmlReportExportFilePicker
{
    public string? SelectDestination(ProjectRecord project) => null;
}
