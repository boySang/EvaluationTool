using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;

namespace AssessmentTool.App.Startup;

public sealed class StartupSuccessMarker
{
    public const string MarkerFileName = "EvaluationTool-startup-success.json";

    private readonly string markerPath;
    private readonly Func<DateTimeOffset> utcNow;
    private readonly Func<int> processId;
    private readonly Func<string> applicationVersion;

    public StartupSuccessMarker()
        : this(
            Path.Combine(Path.GetTempPath(), MarkerFileName),
            () => DateTimeOffset.UtcNow,
            () => Process.GetCurrentProcess().Id,
            GetApplicationVersion)
    {
    }

    public StartupSuccessMarker(
        string markerPath,
        Func<DateTimeOffset> utcNow,
        Func<int> processId,
        Func<string> applicationVersion)
    {
        this.markerPath = string.IsNullOrWhiteSpace(markerPath)
            ? throw new ArgumentException("启动标记路径不能为空。", nameof(markerPath))
            : markerPath;
        this.utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));
        this.processId = processId ?? throw new ArgumentNullException(nameof(processId));
        this.applicationVersion = applicationVersion ?? throw new ArgumentNullException(nameof(applicationVersion));
    }

    public string MarkerPath => markerPath;

    public void BeginStartup()
    {
        TryDelete(markerPath);
    }

    public bool TryMarkMainWindowDisplayed()
    {
        var temporaryPath = markerPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var directory = Path.GetDirectoryName(markerPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var content = string.Format(
                CultureInfo.InvariantCulture,
                "{{\"schemaVersion\":1,\"status\":\"main-window-displayed\",\"processId\":{0},\"timestampUtc\":\"{1:O}\",\"applicationVersion\":\"{2}\"}}",
                processId(),
                utcNow(),
                EscapeJson(applicationVersion()));
            File.WriteAllText(temporaryPath, content, new UTF8Encoding(false));
            TryDelete(markerPath);
            File.Move(temporaryPath, markerPath);
            return true;
        }
        catch
        {
            TryDelete(temporaryPath);
            return false;
        }
    }

    private static string GetApplicationVersion()
    {
        return Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown";
    }

    private static string EscapeJson(string value)
    {
        return (value ?? string.Empty)
            .Replace("\\", "\\\\")
            .Replace("\"", "\\\"")
            .Replace("\r", "\\r")
            .Replace("\n", "\\n");
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }
}
