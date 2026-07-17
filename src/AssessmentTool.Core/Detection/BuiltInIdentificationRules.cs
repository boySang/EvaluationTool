namespace AssessmentTool.Core.Detection;

public static class BuiltInIdentificationRules
{
    private static readonly IdentificationRule LinuxOsReleaseIdRule =
        IdentificationRule.CreateVerified(
            Domain.TargetCategory.Server,
            "^ID=\\\"?(?<vendor>[a-z0-9._-]+)\\\"?$",
            0.95,
            "https://www.freedesktop.org/software/systemd/man/latest/os-release.html");

    private static readonly IdentificationRule HuaweiVrpRule =
        IdentificationRule.CreateVerified(
            Domain.TargetCategory.NetworkDevice,
            "^(?<vendor>Huawei) Versatile Routing Platform Software$",
            0.85,
            "https://info.support.huawei.com/enterprise/en/doc/EDOC1100352648/91652f17/device-status-checking-commands");

    public static IdentificationRule LinuxOsReleaseId => LinuxOsReleaseIdRule;

    public static IdentificationRule HuaweiVrp => HuaweiVrpRule;
}
