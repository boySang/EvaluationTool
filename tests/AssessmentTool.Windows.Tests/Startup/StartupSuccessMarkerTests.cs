using System;
using System.IO;
using AssessmentTool.App.Startup;
using Xunit;

namespace AssessmentTool.Windows.Tests.Startup;

public sealed class StartupSuccessMarkerTests
{
    [Fact]
    public void Default_marker_uses_current_user_temporary_directory()
    {
        var marker = new StartupSuccessMarker();

        Assert.Equal(
            Path.Combine(Path.GetTempPath(), StartupSuccessMarker.MarkerFileName),
            marker.MarkerPath);
    }

    [Fact]
    public void Begin_startup_removes_stale_marker_without_creating_success_marker()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = Path.Combine(directory.Path, StartupSuccessMarker.MarkerFileName);
            File.WriteAllText(path, "stale");
            var marker = CreateMarker(path);

            marker.BeginStartup();

            Assert.False(File.Exists(path));
        }
    }

    [Fact]
    public void Main_window_display_writes_machine_readable_non_sensitive_marker()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = Path.Combine(directory.Path, StartupSuccessMarker.MarkerFileName);
            var marker = CreateMarker(path);
            marker.BeginStartup();

            var written = marker.TryMarkMainWindowDisplayed();

            Assert.True(written);
            var content = File.ReadAllText(path);
            Assert.Contains("\"schemaVersion\":1", content);
            Assert.Contains("\"status\":\"main-window-displayed\"", content);
            Assert.Contains("\"processId\":2468", content);
            Assert.Contains("\"timestampUtc\":\"2026-07-17T00:00:00.0000000+00:00\"", content);
            Assert.Contains("\"applicationVersion\":\"1.2.3.4\"", content);
            Assert.DoesNotContain(Environment.UserName, content);
            Assert.DoesNotContain(directory.Path, content);
        }
    }

    [Fact]
    public void Marker_is_absent_when_main_window_display_is_never_reported()
    {
        using (var directory = new TemporaryDirectory())
        {
            var path = Path.Combine(directory.Path, StartupSuccessMarker.MarkerFileName);
            var marker = CreateMarker(path);

            marker.BeginStartup();

            Assert.False(File.Exists(path));
        }
    }

    [Fact]
    public void Unwritable_marker_location_does_not_crash_the_application()
    {
        using (var directory = new TemporaryDirectory())
        {
            var marker = CreateMarker(directory.Path);

            var written = marker.TryMarkMainWindowDisplayed();

            Assert.False(written);
        }
    }

    private static StartupSuccessMarker CreateMarker(string path)
    {
        return new StartupSuccessMarker(
            path,
            () => new DateTimeOffset(2026, 7, 17, 0, 0, 0, TimeSpan.Zero),
            () => 2468,
            () => "1.2.3.4");
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "EvaluationTool-startup-marker-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, true);
            }
            catch
            {
            }
        }
    }
}
