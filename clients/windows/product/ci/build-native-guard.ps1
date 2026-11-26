param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'

$output=(Resolve-Path -LiteralPath $OutputDirectory).Path
$native=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../native')).Path
$work=Join-Path ([IO.Path]::GetTempPath()) ('oracle-guard-build-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $work
try {
    $common=@('/nologo','/c','/O2','/W4','/MT','/guard:cf','/D_WIN32_WINNT=0x0A00','/DUNICODE','/D_UNICODE')
    & cl.exe @common "/Fo$work/guard.obj" "$native/guard.c"
    if ($LASTEXITCODE) { throw 'Native WFP boundary compile failed' }
    & cl.exe @common /std:c++17 /EHsc "/Fo$work/adapter-bindings.obj" "$native/adapter-bindings.cpp"
    if ($LASTEXITCODE) { throw 'Native adapter bindings compile failed' }
    $dll=Join-Path $work 'Proxy.Guard.dll'
    & link.exe /NOLOGO /DLL /DYNAMICBASE /NXCOMPAT /GUARD:CF /Brepro "/OUT:$dll" "/IMPLIB:$work/Proxy.Guard.lib" "$work/guard.obj" "$work/adapter-bindings.obj" ole32.lib uuid.lib iphlpapi.lib cfgmgr32.lib advapi32.lib setupapi.lib
    if ($LASTEXITCODE) { throw 'Native guard DLL link failed' }

    $exports=@(& dumpbin.exe /NOLOGO /EXPORTS $dll)
    if ($LASTEXITCODE) { throw 'Native guard export inspection failed' }
    foreach ($entry in 'OpGuardApply','OpTunParked','OpParkIpBindings','OpRestoreIpBindings','OpDormantDepartureEvidence') {
        if (@($exports -match ("\s"+$entry+"\s*$")).Count -ne 1) { throw "Missing native guard export $entry" }
    }
    $imports=@(& dumpbin.exe /NOLOGO /DEPENDENTS $dll)
    if ($LASTEXITCODE -or $imports -match '(?i)\b(?:VCRUNTIME|MSVCP|CONCRT)\d+[^\s]*\.dll\b') { throw 'Native guard has an unbundled C++ runtime dependency' }
    Copy-Item -LiteralPath $dll -Destination (Join-Path $output 'Proxy.Guard.dll') -Force
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}
