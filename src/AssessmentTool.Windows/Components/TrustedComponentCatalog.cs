namespace AssessmentTool.Windows.Components;

public static class TrustedComponentCatalog
{
    private static readonly ComponentDefinition TrustedPlink = ComponentDefinition.Plink(
        @"依赖组件\plink.exe",
        "e5621ffe4879f0ec39ed40f688db9399c2d43054d41ef14472fa335c4693b915",
        "0.84.0.0");

    public static ComponentDefinition Plink => TrustedPlink;
}
