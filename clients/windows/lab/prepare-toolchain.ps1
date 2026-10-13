$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Not a disposable GitHub-hosted runner'
}
$sdkZip = Join-Path $env:RUNNER_TEMP 'wireguard-nt-1.1.zip'
Invoke-WebRequest -Uri 'https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip' -OutFile $sdkZip -MaximumRedirection 2
if ((Get-FileHash -Algorithm SHA256 $sdkZip).Hash.ToLowerInvariant() -ne
    'dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace') {
    throw 'Official SDK ZIP integrity check failed'
}
$sdk = Join-Path $env:RUNNER_TEMP 'wg-sdk'
Expand-Archive -LiteralPath $sdkZip -DestinationPath $sdk -Force
$dll = Join-Path $sdk 'wireguard-nt/bin/amd64/wireguard.dll'
$header = Join-Path $sdk 'wireguard-nt/include/wireguard.h'
if (!(Test-Path $dll -PathType Leaf) -or !(Test-Path $header -PathType Leaf)) {
    throw 'Official pinned SDK does not include expected DLL and header'
}
if ((Get-FileHash -Algorithm SHA256 $dll).Hash.ToLowerInvariant() -ne
    'b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3') {
    throw 'Official DLL integrity check failed'
}
if ((Get-AuthenticodeSignature -FilePath $dll).Status -ne 'Valid') {
    throw 'Unsigned or invalid official WireGuardNT native binary'
}
"WG_LAB_DLL=$dll" >> $env:GITHUB_ENV
"WG_LAB_INCLUDE=$(Split-Path $header)" >> $env:GITHUB_ENV

$archive = Join-Path $env:RUNNER_TEMP 'llvm-mingw.zip'
Invoke-WebRequest -Uri 'https://download.wireguard.com/windows-toolchain/distfiles/llvm-mingw-20260311-ucrt-x86_64.zip' -OutFile $archive
if ((Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant() -ne
    'dd4c67d98959479c7be2fb6709ba074475991590848cb9d0eb2620be06b182e1') {
    throw 'Official compiler archive integrity check failed'
}
$tools = Join-Path $env:RUNNER_TEMP 'llvm-mingw'
New-Item -ItemType Directory -Path $tools -Force | Out-Null
& tar -xf $archive -C $tools --strip-components 1
if ($LASTEXITCODE -ne 0) { throw 'Compiler unpacking failed' }
$gcc = Join-Path $tools 'bin/x86_64-w64-mingw32-gcc.exe'
if (!(Test-Path $gcc -PathType Leaf)) { throw 'Pinned compiler unavailable' }
"WG_LAB_GCC=$gcc" >> $env:GITHUB_ENV
Write-Host 'PASS: official signed x64 WireGuardNT DLL and pinned C compiler authenticated'
