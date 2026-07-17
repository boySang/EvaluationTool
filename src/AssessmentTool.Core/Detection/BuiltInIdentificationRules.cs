namespace AssessmentTool.Core.Detection;

public static class BuiltInIdentificationRules
{
    private static readonly IdentificationRule LinuxOsReleaseIdRule =
        IdentificationRule.CreateVerified(
            Domain.TargetCategory.Server,
            "^ID=\\\"?(?<vendor>[a-z0-9._-]+)\\\"?$",
            0.95,
            "https://www.freedesktop.org/software/systemd/man/latest/os-release.html");

    public static IdentificationRule LinuxOsReleaseId => LinuxOsReleaseIdRule;
}
