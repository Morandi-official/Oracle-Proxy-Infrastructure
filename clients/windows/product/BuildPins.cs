namespace OracleProxy.Product;
// CI computes these from checksum-verified upstream archives / native build
// before compilation. Placeholder values must fail verification, never load.
internal static class BuildPins
{
    internal const string Core = "BUILD_MUST_PIN_CORE";
    internal const string Guard = "BUILD_MUST_PIN_GUARD";
}
