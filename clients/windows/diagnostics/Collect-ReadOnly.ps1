# Local, read-only Windows diagnostics. No administrator elevation required by design.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Diagnostics.psm1') -Force -ErrorAction Stop
Get-ReadOnlyWindowsDiagnostics | ConvertTo-Json -Depth 8
