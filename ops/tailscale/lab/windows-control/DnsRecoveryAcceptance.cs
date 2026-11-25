using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace OracleProxy.Tailscale;

internal static class DnsRecoveryAcceptance
{
    internal static async Task<int> Run(string trustedEngine, string state)
    {
        if (Environment.GetEnvironmentVariable("GITHUB_EVENT_NAME") != "pull_request" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted")
            throw new IOException("DISPOSABLE_WINDOWS_RUNNER_REQUIRED");

        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        using (var account = new AccountClient())
        {
            var prep = Stopwatch.StartNew();
            var route = await account.PrepareLogin(limit.Token);
            if (route?.StartsWith("encrypted-dns-", StringComparison.Ordinal) != true)
                throw new IOException("LAB_ACCOUNT_DNS_FALLBACK_MISSING");
            Console.WriteLine($"ACCOUNT_DNS_FALLBACK={route} PREPARATION_MS={prep.ElapsedMilliseconds}");
            var login = Stopwatch.StartNew();
            try
            {
                // No registered user or password is supplied. Only the API's
                // authenticated HTTPS response and the prepared socket are tested.
                await account.Login("proxy-route-check", "", new string('0', 64), limit.Token);
                throw new IOException("LAB_EMPTY_PASSWORD_ACCEPTED");
            }
            catch (IOException error) when (error.Message == "INVALID_CREDENTIALS")
            {
                Console.WriteLine($"WARM_LOGIN_POST_RESPONSE_MS={login.ElapsedMilliseconds}");
            }
        }

        const string host = "proxy-coordinator.test";
        var coordinator = new Uri("https://" + host);
        var listener = new TcpListener(IPAddress.Loopback, 443);
        listener.Start();
        try
        {
            await DaemonProcess.CacheVerifiedCoordinatorAddress(state, coordinator, IPAddress.Loopback, limit.Token);
            await using var daemon = await DaemonProcess.Start(trustedEngine, state, limit.Token);
            var observe = ObserveServerName(listener, limit.Token);
            var credential = "hskey-auth-" + new string('a', 12) + "-" + new string('b', 64);
            await daemon.Control.Enroll(coordinator, credential, limit.Token);
            if (!string.Equals(await observe, host, StringComparison.OrdinalIgnoreCase))
                throw new IOException("LAB_ENGINE_DNS_CACHE_TLS_IDENTITY_MISSING");
            Console.WriteLine("ENGINE_DNS_CACHE_TLS_CLIENT_HELLO=PASS");
            return 0;
        }
        finally { listener.Stop(); }
    }

    private static async Task<string?> ObserveServerName(TcpListener listener, CancellationToken cancel)
    {
        using var connection = await listener.AcceptTcpClientAsync(cancel);
        using var tls = new SslStream(connection.GetStream());
        string? name = null;
        try
        {
            await tls.AuthenticateAsServerAsync((_, hello, _, _) =>
            {
                name = hello.ServerName;
                // This fixture neither authenticates nor enrolls a device.
                // Observe the original name and terminate the handshake.
                return ValueTask.FromException<SslServerAuthenticationOptions>(new AuthenticationException());
            }, null, cancel);
        }
        catch (AuthenticationException) when (name is not null) { }
        return name;
    }
}
