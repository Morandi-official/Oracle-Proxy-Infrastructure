# Optional diagnostic for a clean hosted Windows runner after Proxy disconnect.
# The four ranges partition a pinned immutable mirror object, so every byte is
# authenticated by the release SHA-256. No application account or upload.
param([Parameter(Mandatory)][string]$ReportPath)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:GITHUB_REF -ne 'refs/heads/main') {
    throw 'HOSTED_MAIN_ORIGIN_BENCHMARK_REQUIRED'
}
if (@(Get-NetAdapter -Name 'ProxyTail-*' -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'PROXY_ADAPTER_STILL_PRESENT'
}

$server = 'vpn-admin.morandi.dpdns.org'
$origin = '152.67.156.100'
$path = '/downloads/v0.3.0-rc31/Proxy-0.3.0-rc31-win-x64-2e1e584fd2d7.zip'
[long]$size = 63619881
$sha = 'd3b3b896deef0dd86e8f5f7a3a985d6554601e580e2e0ffd248e6c6b1ccef110'
$url = "https://$server$path"

$selection = @(Find-NetRoute -RemoteIPAddress $origin)
$address = @($selection | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetIPAddress' })
$route = @($selection | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' })
if ($address.Count -ne 1 -or $route.Count -ne 1 -or
    $address[0].InterfaceIndex -ne $route[0].InterfaceIndex -or
    $address[0].InterfaceAlias -match 'ProxyTail|Tailscale|WireGuard|Loopback') {
    throw 'DIRECT_ROUTE_UNVERIFIED'
}
$source = $address[0].IPAddress
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
if (!(Test-Path -LiteralPath $curl -PathType Leaf)) { throw 'SYSTEM_CURL_UNAVAILABLE' }
$work = Join-Path $env:RUNNER_TEMP ('proxy-origin-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory $work
$jobs = @()
$hasher = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
try {
    $rangeMs = 25000
    [long]$stripe = [Math]::Ceiling($size / 4.0)
    if ($stripe -gt 16MB) { throw 'RANGE_CAP_EXCEEDED' }
    $started = [DateTimeOffset]::UtcNow
    $timer = [Diagnostics.Stopwatch]::StartNew()
    for ($index = 0; $index -lt 4; $index++) {
        [long]$from = $index * $stripe
        [long]$to = [Math]::Min($size - 1, $from + $stripe - 1)
        [long]$length = $to - $from + 1
        $body = Join-Path $work "part-$index"
        $headers = Join-Path $work "headers-$index"
        $launch = [Diagnostics.ProcessStartInfo]::new($curl)
        $launch.UseShellExecute = $false
        $launch.CreateNoWindow = $true
        $launch.RedirectStandardOutput = $true
        $launch.RedirectStandardError = $true
        $arguments = @('--disable', '--ipv4', '--silent', '--show-error', '--fail', '--noproxy', '*',
            '--proto', '=https', '--max-redirs', '0', '--connect-timeout', '4', '--max-time', '25',
            '--resolve', "${server}:443:$origin", '--interface', $source, '--header', 'Accept-Encoding: identity',
            '--range', "$from-$to", '--max-filesize', "$length", '--dump-header', $headers,
            '--output', $body, '--write-out', '%{json}', $url)
        foreach ($argument in $arguments) { $launch.ArgumentList.Add($argument) }
        $process = [Diagnostics.Process]::Start($launch)
        $jobs += [pscustomobject]@{
            Process = $process
            Output = $process.StandardOutput.ReadToEndAsync()
            ErrorOutput = $process.StandardError.ReadToEndAsync()
            From = $from
            To = $to
            Length = $length
            Body = $body
            Headers = $headers
        }
    }
    foreach ($job in $jobs) {
        $remaining = [int][Math]::Max(0, $rangeMs + 2000 - $timer.ElapsedMilliseconds)
        if (!$job.Process.WaitForExit($remaining)) { throw 'ORACLE_ORIGIN_RANGE_DEADLINE' }
    }
    $timer.Stop()
    $ended = [DateTimeOffset]::UtcNow

    $streams = @()
    $readBuffer = [byte[]]::new(65536)
    foreach ($job in $jobs) {
        if ($job.Process.ExitCode -ne 0) { throw 'ORACLE_ORIGIN_RANGE_REQUEST_FAILED' }
        $out = $job.Output.GetAwaiter().GetResult() | ConvertFrom-Json
        if ($out.http_code -ne 206 -or $out.remote_ip -ne $origin -or $out.remote_port -ne 443 -or
            $out.local_ip -ne $source -or $out.ssl_verify_result -ne 0 -or $out.num_redirects -ne 0 -or
            $out.url_effective -cne $url -or $out.size_download -ne $job.Length) {
            throw 'ORACLE_ORIGIN_RANGE_SOURCE_OR_STATUS_MISMATCH'
        }
        $range = "bytes $($job.From)-$($job.To)/$size"
        $headers = @(Get-Content -LiteralPath $job.Headers | Where-Object { $_ -match '^Content-Range:' })
        if ($headers.Count -ne 1 -or $headers[0].Substring('Content-Range:'.Length).Trim() -cne $range -or
            (Get-Item -LiteralPath $job.Body).Length -ne $job.Length) {
            throw 'ORACLE_ORIGIN_RANGE_LENGTH_MISMATCH'
        }
        $bytes = [IO.File]::OpenRead($job.Body)
        try {
            while (($read = $bytes.Read($readBuffer, 0, $readBuffer.Length)) -gt 0) {
                $hasher.AppendData($readBuffer, 0, $read)
            }
        }
        finally { $bytes.Dispose() }
        $streams += [ordered]@{
            bytes = $job.Length
            https_connect_ms = [Math]::Round(1000.0 * $out.time_appconnect, 2)
            first_byte_ms = [Math]::Round(1000.0 * $out.time_starttransfer, 2)
            total_ms = [Math]::Round(1000.0 * $out.time_total, 2)
            http_version = $out.http_version
        }
    }
    if ([Convert]::ToHexString($hasher.GetHashAndReset()).ToLowerInvariant() -cne $sha) {
        throw 'ORACLE_ORIGIN_ASSET_DIGEST_MISMATCH'
    }

    [ordered]@{
        status = 'OBSERVED'
        path = 'direct_oracle_https'
        target = $url
        started_at = $started.ToString('o')
        ended_at = $ended.ToString('o')
        streams = $streams
        total_bytes = $size
        elapsed_ms = $timer.ElapsedMilliseconds
        throughput_mbps = [Math]::Round(8.0 * $size / $timer.Elapsed.TotalSeconds / 1e6, 2)
        sha256_verified = $true
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding utf8
}
finally {
    foreach ($job in $jobs) {
        try {
            if (!$job.Process.HasExited) {
                $job.Process.Kill()
                $null = $job.Process.WaitForExit(1000)
            }
        }
        finally { $job.Process.Dispose() }
    }
    $hasher.Dispose()
    Remove-Item -LiteralPath $work -Recurse -Force
}
