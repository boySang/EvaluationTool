using AssessmentTool.Core.Detection;
using AssessmentTool.Core.Domain;
using Xunit;

namespace AssessmentTool.Core.Tests.Detection;

public sealed class BuiltInIdentificationRulesTests
{
    [Theory]
    [InlineData("ID=ubuntu", "ubuntu")]
    [InlineData("ID=\"kylin\"", "kylin")]
    [InlineData("ID=uos", "uos")]
    public void Linux_os_release_rule_identifies_vendor_without_guessing_version(
        string line,
        string expectedVendor)
    {
        var result = new DetectionEngine().Detect(
            line,
            new[] { BuiltInIdentificationRules.LinuxOsReleaseId });

        var candidate = Assert.Single(result.Candidates);
        Assert.Equal(TargetCategory.Server, candidate.Category);
        Assert.Equal(expectedVendor, candidate.Vendor);
        Assert.Null(candidate.Version);
        Assert.Equal(0.95, candidate.Confidence);
    }
}
