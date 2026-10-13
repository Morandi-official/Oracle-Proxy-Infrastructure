$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path './dist/loopback' -Force | Out-Null
& $env:WG_LAB_GCC -std=gnu11 -O2 -Wall -Wextra -I $env:WG_LAB_INCLUDE './clients/windows/lab/wgnt-loopback.c' -o './dist/loopback/wgnt-loopback.exe' -lws2_32
if ($LASTEXITCODE -ne 0) { throw 'Native test compilation failed' }
Write-Host 'PASS: isolated integration program compiled'
