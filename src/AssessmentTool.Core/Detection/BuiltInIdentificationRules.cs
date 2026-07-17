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

    private static readonly IdentificationRule H3cComwareRule =
        IdentificationRule.CreateVerified(
            Domain.TargetCategory.NetworkDevice,
            "^(?<vendor>H3C) (?<productFamily>Comware)(?: Platform)? Software, Version (?<version>(?:7|9)\\.[0-9.]+)(?:, .+)?$",
            0.85,
            "https://www.h3c.com/cn/d_202503/2368787_30005_0.htm");

    public static IdentificationRule LinuxOsReleaseId => LinuxOsReleaseIdRule;

    public static IdentificationRule HuaweiVrp => HuaweiVrpRule;

    public static IdentificationRule H3cComware => H3cComwareRule;
}
