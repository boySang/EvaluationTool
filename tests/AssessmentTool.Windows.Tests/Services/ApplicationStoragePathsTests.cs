using System;
using System.Data.SQLite;
using System.IO;
using AssessmentTool.App.Services;
using Xunit;

namespace AssessmentTool.Windows.Tests.Services;

public sealed class ApplicationStoragePathsTests
{
    [Fact]
    public void Create_builds_database_and_credential_paths_under_trusted_user_root()
    {
        var root = Path.Combine(Path.GetTempPath(), "EvaluationTool.Paths", Guid.NewGuid().ToString("N"));
        try
        {
            var paths = ApplicationStoragePaths.Create(root);
            var connection = new SQLiteConnectionStringBuilder(paths.SqliteConnectionString);

            Assert.Equal(Path.GetFullPath(root), paths.RootDirectory);
            Assert.Equal(Path.Combine(Path.GetFullPath(root), "data", "assessment.db"), paths.DatabasePath);
            Assert.Equal(Path.Combine(Path.GetFullPath(root), "security"), paths.CredentialRootDirectory);
            Assert.Equal(paths.DatabasePath, Path.GetFullPath(connection.DataSource));
            Assert.True(Directory.Exists(paths.RootDirectory));
            Assert.True(Directory.Exists(Path.GetDirectoryName(paths.DatabasePath)));
            Assert.True(Directory.Exists(paths.CredentialRootDirectory));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Create_rejects_blank_root(string? root)
    {
        Assert.ThrowsAny<ArgumentException>(() => ApplicationStoragePaths.Create(root));
    }
}
