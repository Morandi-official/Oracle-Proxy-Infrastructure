# Runs under Windows PowerShell STA for UI Automation of the actual packaged EXE.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'DISPOSABLE_HOSTED_WINDOWS_REQUIRED'}
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BootstrapUiClick {
 [DllImport("user32.dll",SetLastError=true)] public static extern bool PostMessage(IntPtr window,uint message,IntPtr first,IntPtr second);
}
'@
$root=Join-Path $env:ProgramFiles 'OracleProxy'
$state=Join-Path $env:ProgramData 'OracleProxy'
if((Get-Service OracleProxyService,OracleProxyRecovery -ErrorAction SilentlyContinue) -or (Test-Path $root) -or (Test-Path $state)){throw 'PREEXISTING_INSTALLATION_REFUSED'}
$work=Join-Path $env:RUNNER_TEMP 'proxy-real-portable-bootstrap'
New-Item -ItemType Directory -Force $work | Out-Null
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$fixture=(Resolve-Path './dist/product-tests/OracleProxy.Product.Tests.exe').Path
$candidate=@(Get-ChildItem ./dist/candidate/*.zip | Where-Object Name -NotLike '*-source.zip')
if($candidate.Count -ne 1){throw 'EXACT_PACKAGED_PORTABLE_REQUIRED'}
Expand-Archive $candidate[0].FullName (Join-Path $work 'candidate')
$exe=@(Get-ChildItem (Join-Path $work 'candidate') -Filter Proxy.exe -Recurse)
if($exe.Count -ne 1){throw 'ONE_PACKAGED_CLIENT_REQUIRED'}
$exe=$exe[0].FullName
$package=Split-Path $exe
foreach($baseline in @(
 @('rc35','b28a72c8e0c5','9311ee09a114f5f600c5304162087780f58f9cfb4fb088022a6ba3d0ebebc3ed'),
 @('rc36','7b1f2885c605','130dea24feaf9838caeeb0048d47ef7680386a18baaa8ecf9ebf6a2233ecc825'))){
 $zip=Join-Path $work ($baseline[0]+'.zip')
 $url='https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/releases/download/v0.3.0-'+$baseline[0]+'/Proxy-0.3.0-'+$baseline[0]+'-win-x64-'+$baseline[1]+'.zip'
 Invoke-WebRequest $url -OutFile $zip -UseBasicParsing -TimeoutSec 120
 if((Get-FileHash $zip).Hash -ne $baseline[2]){throw 'PUBLISHED_BASELINE_MISMATCH'}
 Expand-Archive $zip (Join-Path $work $baseline[0])
}
$old=@(Get-ChildItem (Join-Path $work 'rc35') -Filter Proxy.exe -Recurse)[0].FullName
$brokenRelease=@(Get-ChildItem (Join-Path $work 'rc36') -Filter Proxy.exe -Recurse)[0].FullName
$script:gui=$null
function Wait-For([scriptblock]$Check,[string]$Failure,[int]$Seconds=45){
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while($watch.Elapsed.TotalSeconds -lt $Seconds){if(& $Check){return};Start-Sleep -Milliseconds 100}
 throw $Failure
}
function Element([string]$Id){
 if(!$script:gui -or $script:gui.HasExited){return $null}
 try{
  $script:gui.Refresh();$handle=$script:gui.MainWindowHandle
  if($handle -eq [IntPtr]::Zero){return $null}
  $window=[Windows.Automation.AutomationElement]::FromHandle($handle)
  $condition=New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty,$Id)
  return $window.FindFirst([Windows.Automation.TreeScope]::Descendants,$condition)
 }catch [Windows.Automation.ElementNotAvailableException]{return $null}
}
function Enabled([string]$Id){$e=Element $Id;return $null -ne $e -and $e.Current.IsEnabled -and !$e.Current.IsOffscreen}
function Feedback { $e=Element 'login-feedback';if($e){return $e.Current.Name};return '' }
function Click([string]$Id){
 $e=Element $Id;if(!$e -or !$e.Current.IsEnabled){throw ('UI_BUTTON_NOT_AVAILABLE_'+$Id)}
 if(![BootstrapUiClick]::PostMessage([IntPtr]$e.Current.NativeWindowHandle,0x00F5,[IntPtr]::Zero,[IntPtr]::Zero)){throw 'UI_CLICK_POST_FAILED'}
}
function Launch([string]$Client){
 $script:gui=Start-Process $Client -PassThru
 Wait-For { $script:gui.Refresh();$script:gui.MainWindowHandle -ne [IntPtr]::Zero } 'PACKAGED_GUI_NOT_SHOWN' 20
}
function Close-Gui {
 $null=$script:gui.CloseMainWindow()
 if(!$script:gui.WaitForExit(15000)){throw 'REAL_WINDOW_X_DID_NOT_CLOSE'}
 $script:gui.Dispose();$script:gui=$null
}
function Run-Step([string]$Client,[string[]]$Arguments,[int]$Expected=0){
 $p=Start-Process $Client -ArgumentList $Arguments -PassThru
 try{if(!$p.WaitForExit(90000)){throw 'FIXED_WORKER_TIMEOUT'};if($p.ExitCode -ne $Expected){throw ('FIXED_WORKER_EXIT_'+$p.ExitCode)}}finally{$p.Dispose()}
}
function Remove-Owned {
 if(Get-Service OracleProxyService -ErrorAction SilentlyContinue){Run-Step $exe @('--uninstall')}
 Wait-For { !(Get-Service OracleProxyService -ErrorAction SilentlyContinue) } 'OWNED_SERVICE_NOT_REMOVED' 10
 if((Test-Path $root) -or (Test-Path $state)){throw 'OWNED_DIRECTORIES_NOT_REMOVED'}
}
$probeUser='ProxyBootstrapOwner'
if(Get-LocalUser $probeUser -ErrorAction SilentlyContinue){throw 'PREEXISTING_TEST_USER_REFUSED'}
$password=ConvertTo-SecureString ('Q!a'+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
$credential=New-Object Management.Automation.PSCredential("$env:COMPUTERNAME\$probeUser",$password)
function Probe-Standard([string]$Case){
 $stdout=Join-Path $work ('scm-probe-'+$Case+'.out')
 $stderr=Join-Path $work ('scm-probe-'+$Case+'.err')
 $p=Start-Process $fixture -ArgumentList @('--bootstrap-scm-probe',$Case) -Credential $credential -WorkingDirectory $env:WINDIR -LoadUserProfile -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
 try{
  $ended=$p.WaitForExit(20000)
  Write-Host ('SCM_PROBE_PROCESS='+$Case+';ENDED='+$ended+';EXIT='+$p.ExitCode)
  if(Test-Path $stdout){Get-Content $stdout | Where-Object {$_ -match '^SCM_PROBE_'} | Write-Host}
  if($p.ExitCode -ne 0 -and (Test-Path $stderr)){Get-Content $stderr | Select-Object -First 4 | Write-Host}
  if(!$ended -or $p.ExitCode -ne 0){throw ('STANDARD_USER_BOOTSTRAP_FAILED_'+$Case)}
 }finally{if(!$p.HasExited){$p.Kill();$p.WaitForExit()};$p.Dispose()}
}
try {
 New-LocalUser $probeUser -Password $password -AccountNeverExpires -PasswordNeverExpires | Out-Null
 Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $probeUser
 # Reproduce the shipped rc36 first-start defect with no CLI preinstallation.
 Launch $brokenRelease
 Wait-For { (Enabled 'bootstrap-retry') -and !(Enabled 'login') } 'PUBLISHED_RC36_FRESH_DEFECT_NOT_REPRODUCED'
 Close-Gui
 Write-Host 'PUBLISHED_RC36_FRESH_GUI_INITIALIZATION_FAILURE_REPRODUCED=PASS'
 # Start the real candidate EXE alone: missing runtime must be explicit and
 # closable. Retry in the SAME real window after restoring the actual payload.
 $incomplete=Join-Path $work 'incomplete';New-Item -ItemType Directory $incomplete | Out-Null
 Copy-Item $exe (Join-Path $incomplete 'Proxy.exe')
 Launch (Join-Path $incomplete 'Proxy.exe')
 Wait-For { (Feedback) -match 'CLIENT_PACKAGE_INCOMPLETE' -and (Enabled 'bootstrap-retry') -and !(Enabled 'login') } 'MISSING_PAYLOAD_NOT_EXPLAINED'
 if(!(Enabled 'copy-startup-diagnostics')){throw 'LOGIN_DIAGNOSTICS_UNREACHABLE'}
 Close-Gui
 if(Get-Service OracleProxyService -ErrorAction SilentlyContinue){throw 'INCOMPLETE_PACKAGE_CREATED_SERVICE'}
 Launch (Join-Path $incomplete 'Proxy.exe')
 Wait-For { (Feedback) -match 'CLIENT_PACKAGE_INCOMPLETE' } 'RETRY_PRECONDITION_FAILED'
 Copy-Item (Join-Path $package 'runtime') $incomplete -Recurse
 Click 'bootstrap-retry'
 Wait-For { Enabled 'login' } 'FRESH_REAL_PORTABLE_RETRY_DID_NOT_ENABLE_LOGIN' 70
 Write-Host 'ACTUAL_PORTABLE_MISSING_RUNTIME_EXPLICIT_CLOSE_AND_SAME_WINDOW_RETRY=PASS'
 # The actual shipped GUI -> confirmation -> runas worker -> SYSTEM recovery
 # -> authenticated fresh attachment -> enabled Login path, without CLI setup.
 Click 'emergency-recovery'
 Wait-For {
  $condition=New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty,$script:gui.Id)
  $windows=[Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,$condition)
  foreach($w in $windows){
   if($w.Current.Name -eq '恢复直连'){
    $ok=$w.FindFirst([Windows.Automation.TreeScope]::Descendants,(New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty,'1')))
    if($ok){$ok.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke();return $true}
   }
  };return $false
 } 'RECOVERY_CONFIRMATION_NOT_FOUND' 10
 Wait-For { (Feedback) -match '恢复程序已完成' -and (Enabled 'login') -and (Enabled 'emergency-recovery') } 'REAL_GUI_RECOVERY_DID_NOT_REATTACH_ENABLE_LOGIN' 70
 Close-Gui
 Wait-For { (Get-Service OracleProxyService).Status -eq 'Stopped' } 'REAL_GUI_X_DID_NOT_STOP_BACKEND' 15
 Remove-Owned
 Write-Host 'ACTUAL_PORTABLE_FIRST_GUI_UAC_RECOVERY_LOGIN_REATTACH_AND_X=PASS'
 Probe-Standard 'absent'
 # Real old payload / stopped service reproduces the user's exact diagnostic.
 Run-Step $old @('--install',$owner)
 Stop-Service OracleProxyService
 # Old ACL without owner SERVICE_START: same boundary as a standard old owner.
 & sc.exe sdset OracleProxyService ('D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;LC;;;'+(Get-LocalUser $probeUser).SID.Value+')') | Out-Null
 if($LASTEXITCODE -ne 0){throw 'OLD_STANDARD_USER_ACL_FIXTURE_FAILED'}
 Probe-Standard 'denied'
 Run-Step $brokenRelease @('--recover') 3
 $diagnostic=Get-Content (Join-Path $root 'diagnostics.json') -Raw | ConvertFrom-Json
 if($diagnostic.code -ne 'BUNDLE_INTEGRITY_FAILED'){throw 'PUBLISHED_OLD_PAYLOAD_RECOVERY_DEFECT_NOT_REPRODUCED'}
 Write-Host 'PUBLISHED_RC36_RECOVERY_VS_RC35_BUNDLE_INTEGRITY_FAILED_REPRODUCED=PASS'
 Run-Step $exe @('--recover')
 if((Get-FileHash (Join-Path $root 'Proxy.Service.exe')).Hash -ne (Get-FileHash $exe).Hash){throw 'RECOVERY_USED_STALE_HOST'}
 if((Get-FileHash (Join-Path $root 'Proxy.Guard.dll')).Hash -ne (Get-FileHash (Join-Path $package 'runtime/Proxy.Guard.dll')).Hash){throw 'RECOVERY_USED_STALE_NATIVE_BOUNDARY'}
 if((Get-Content (Join-Path $root 'owner.sid') -Raw).Trim() -ne $owner){throw 'RECOVERY_CHANGED_OWNER'}
 Launch $exe
 Wait-For { Enabled 'login' } 'UPGRADED_OLD_RECOVERY_GUI_NOT_READY' 60
 Close-Gui
 Remove-Owned
 Write-Host 'STANDARD_USER_ABSENT_AND_OLD_NO_START_PERMISSION_REACH_ELEVATION=PASS'
 Write-Host 'REAL_RC35_TO_CURRENT_PORTABLE_RECOVERY_REPAIRS_HOST_NATIVE_AND_LOGIN=PASS'
 # Ordinary portable first startup upgrades a stopped old service on its own.
 Run-Step $old @('--install',$owner)
 Stop-Service OracleProxyService
 Launch $exe
 Wait-For { Enabled 'login' } 'ACTUAL_GUI_OLD_SERVICE_UPGRADE_NOT_READY' 70
 if((Get-FileHash (Join-Path $root 'Proxy.Service.exe')).Hash -ne (Get-FileHash $exe).Hash){throw 'GUI_UPGRADE_NOT_CURRENT_HOST'}
 Close-Gui
 Remove-Owned
 Write-Host 'REAL_RC35_STOPPED_TO_CURRENT_FIRST_PORTABLE_GUI_UPGRADE=PASS'
 Write-Host 'GUI_QA_LIMITATION=HOSTED_ELEVATED_DESKTOP_RUNAS_REAL_WORKER;INTERACTIVE_NONADMIN_SECURE_DESKTOP_NOT_EMULATED'
} finally {
 if($script:gui -and !$script:gui.HasExited){$script:gui.Kill();$script:gui.WaitForExit()}
 if(Get-Service OracleProxyService -ErrorAction SilentlyContinue){Run-Step $exe @('--recover');Run-Step $exe @('--uninstall')}
 Remove-LocalUser $probeUser -ErrorAction SilentlyContinue
}
