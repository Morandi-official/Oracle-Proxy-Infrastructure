namespace OracleProxy.Windows.Preview;

// R54: Windows native read-only diagnostic path. No PowerShell interpreter,
// execution-policy bypass or external diagnostic scripts are launched.
internal sealed record DiagnosticSnapshot(
    int PhysicalAdapterCount, bool IPv4DefaultRoute, bool IPv6DefaultRoute,
    string WireSockDriverState, string WireSockServiceState,
    string WireGuardManagerState, bool UuServerPresent, string CollectedAtUtc);

internal static class SanitizedDiagnostics
{
    public static Task<DiagnosticSnapshot> CollectAsync(CancellationToken cancellationToken) =>
        Task.Run(NativeReadOnlyDiagnostics.Collect, cancellationToken);
}
