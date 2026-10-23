$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path './dist/loopback' -Force | Out-Null
& $env:WG_LAB_GCC -std=gnu11 -O2 -Wall -Wextra -municode -I $env:WG_LAB_INCLUDE './clients/windows/lab/wgnt-loopback.c' -o './dist/loopback/wgnt-loopback.exe' -lws2_32
if ($LASTEXITCODE -ne 0) { throw 'Native test compilation failed' }
& $env:WG_LAB_GCC -std=gnu11 -O2 -Wall -Wextra -municode -DR44_CI_DPAPI_MEMORY -I $env:WG_LAB_INCLUDE './clients/windows/lab/wgnt-loopback.c' -o './dist/loopback/wgnt-r44-dpapi-native.exe' -lws2_32 -lcrypt32
if ($LASTEXITCODE -ne 0) { throw 'R44 DPAPI-to-native-memory driver probe compilation failed' }
Write-Host 'PASS: isolated integration program compiled'
