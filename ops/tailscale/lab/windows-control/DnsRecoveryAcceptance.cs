using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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
        var now = DateTimeOffset.UtcNow;
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Disposable Proxy DNS Test", rootKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var root = rootRequest.CreateSelfSigned(now.AddMinutes(-2), now.AddMinutes(10));
        using var publicRoot = X509CertificateLoader.LoadCertificate(root.Export(X509ContentType.Cert));

        using var serverKey = RSA.Create(2048);
        var serverRequest = new CertificateRequest("CN=" + host, serverKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(host);
        serverRequest.CertificateExtensions.Add(names.Build());
        serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
        using var leaf = serverRequest.Create(root, now.AddMinutes(-1), now.AddMinutes(8), RandomNumberGenerator.GetBytes(16));
        using var generated = leaf.CopyWithPrivateKey(serverKey);
        using var keyPair = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx),
            (string?)null, X509KeyStorageFlags.UserKeySet);
        using var trust = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        trust.Open(OpenFlags.ReadWrite);

        var listener = new TcpListener(IPAddress.Loopback, 443);
        listener.Start();
        try
        {
            Console.WriteLine("INSTALLING_DISPOSABLE_TEST_TLS_ROOT");
            trust.Add(publicRoot);
            Console.WriteLine("DISPOSABLE_TEST_TLS_ROOT_READY");
            await DaemonProcess.CacheVerifiedCoordinatorAddress(state, coordinator, IPAddress.Loopback, limit.Token);
            await using var daemon = await DaemonProcess.Start(trustedEngine, state, limit.Token, coordinatorTlsHost: host);
            var observe = ObserveDelayedRequest(listener, host, keyPair, publicRoot, limit.Token);
            var credential = "hskey-auth-" + new string('a', 12) + "-" + new string('b', 64);
            await daemon.Control.Enroll(coordinator, credential, limit.Token);
            await observe;
            Console.WriteLine("ENGINE_DNS_CACHE_AND_DELAYED_VERIFIED_TLS=PASS");
            return 0;
        }
        finally
        {
            listener.Stop();
            trust.Remove(publicRoot);
        }
    }

    private static async Task ObserveDelayedRequest(TcpListener listener, string host, X509Certificate2 certificate,
        X509Certificate2 root, CancellationToken cancel)
    {
        using var connection = await listener.AcceptTcpClientAsync(cancel);
        using var tls = new SslStream(connection.GetStream());
        var context = SslStreamCertificateContext.Create(certificate, new X509Certificate2Collection(root), offline: true);
        await tls.AuthenticateAsServerAsync(async (_, hello, _, token) =>
        {
            if (!string.Equals(hello.ServerName, host, StringComparison.OrdinalIgnoreCase))
                throw new IOException("LAB_ENGINE_TLS_SERVER_NAME_UNEXPECTED");
            await Task.Delay(TimeSpan.FromMilliseconds(8500), token);
            return new SslServerAuthenticationOptions
            {
                ServerCertificateContext = context,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            };
        }, null, cancel);

        using var reader = new StreamReader(tls, Encoding.ASCII, leaveOpen: true);
        var request = await reader.ReadLineAsync(cancel);
        if (request?.StartsWith("GET /key?v=", StringComparison.Ordinal) != true)
            throw new IOException("LAB_ENGINE_COORDINATOR_KEY_REQUEST_MISSING");
        // The fixture never completes enrollment and does not use production credentials.
        await tls.WriteAsync("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"u8.ToArray(), cancel);
    }
}
