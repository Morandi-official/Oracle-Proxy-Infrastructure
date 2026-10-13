$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Only disposable GitHub-hosted Windows runners allowed'
}
New-Item -ItemType Directory -Path './dist/upstream-test' -Force | Out-Null
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '1'
$env:CC = $env:WG_LAB_GCC
$env:CGO_CFLAGS = '-O3 -Wall -Wno-unused-function -Wno-switch -std=gnu11 -DWINVER=0x0A00'
go -C ./upstream build -overlay .overlay/overlay.json -buildmode c-shared -ldflags="-w -s" -trimpath -o ../dist/upstream-test/tunnel.dll ./embeddable-dll-service
if ($LASTEXITCODE -ne 0 -or !(Test-Path './dist/upstream-test/tunnel.dll')) {
    throw 'Official upstream tunnel.dll cannot be built at pinned source revision'
}
dotnet publish ./clients/windows/service-host/OracleProxy.WireGuardHost.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:DebugType=None -o ./dist/service-host
if ($LASTEXITCODE -ne 0) { throw 'Lab service host publish failed' }
New-Item -ItemType Directory -Path './dist/loopback' -Force | Out-Null
& $env:WG_LAB_GCC -std=gnu11 -O2 -Wall -Wextra -municode -I $env:WG_LAB_INCLUDE './clients/windows/lab/wgnt-service-observe.c' -o './dist/loopback/wgnt-service-observe.exe' -lws2_32
if ($LASTEXITCODE -ne 0) { throw 'Read-only SCM handshake observer failed to compile' }
dotnet publish ./clients/windows/manager/OracleProxy.LabManager.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:DebugType=None -o ./dist/lab-admin-manager
if ($LASTEXITCODE -ne 0) { throw 'Lab manager build failed' }
dotnet publish ./clients/windows/app/OracleProxy.Windows.Preview.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:DebugType=None -o ./dist/lab-client-gui
if ($LASTEXITCODE -ne 0) { throw 'Lab GUI build failed' }
Write-Host 'PASS: official tunnel DLL, service host, admin manager, native GUI and observer compiled'
