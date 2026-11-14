param([Parameter(Mandatory=$true)][string]$Client,[Parameter(Mandatory=$true)][string]$SnapshotReader)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_REF -ne 'refs/heads/main'){throw 'MAIN_DISPOSABLE_WINDOWS_REQUIRED'}
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ProxyGuiCloseButton {
 [DllImport("user32.dll", SetLastError=true)]
 public static extern bool PostMessage(IntPtr hwnd,uint message,IntPtr wParam,IntPtr lParam);
}
'@
$gui=Start-Process -FilePath $Client -PassThru
function Find-Control([string]$Id){
 $gui.Refresh();if($gui.HasExited){throw 'LIVE_GUI_EXITED'}
 if($gui.MainWindowHandle -eq [IntPtr]::Zero){return $null}
 $window=[Windows.Automation.AutomationElement]::FromHandle($gui.MainWindowHandle)
 $condition=New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty,$Id)
 return $window.FindFirst([Windows.Automation.TreeScope]::Descendants,$condition)
}
function Await-Mode([string]$Prefix,[bool]$RequireStopped){
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while($watch.Elapsed.TotalSeconds -lt 30){
  $status=Find-Control 'connection-status'
  if($status -and $status.Current.Name.StartsWith($Prefix)){
   $connect=Find-Control 'connect'
   if(!$RequireStopped -or ((Get-Service OracleProxyService).Status -eq 'Stopped' -and $connect -and $connect.Current.IsEnabled)){return}
  }
  Start-Sleep -Milliseconds 20
 }
 throw 'LIVE_GUI_MODE_OR_BACKEND_NOT_CONFIRMED'
}
function Service-Witness([string]$Phase){
 try {
  $service=Get-CimInstance Win32_Service -Filter "Name='OracleProxyService'"
  Write-Host "ACTUAL_X_${Phase}_SERVICE_STATE=$($service.State)"
  Write-Host "ACTUAL_X_${Phase}_SERVICE_PID=$($service.ProcessId)"
  Write-Host "ACTUAL_X_${Phase}_SERVICE_EXIT_CODE=$($service.ExitCode)"
  Write-Host "ACTUAL_X_${Phase}_SERVICE_SPECIFIC_EXIT_CODE=$($service.ServiceSpecificExitCode)"
 } catch {Write-Host "ACTUAL_X_${Phase}_SCM_WITNESS=UNAVAILABLE"}
}
function Exit-FailureWitness {
 Service-Witness 'AFTER'
 try {
  $path=Join-Path $env:ProgramFiles 'OracleProxy/diagnostics.json'
  if(Test-Path -LiteralPath $path){
   $value=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
   foreach($field in @('stage','code','category')){
    $item=[string]$value.$field
    if($item -match '^[A-Za-z0-9_]{1,80}$'){Write-Host "ACTUAL_X_DIAGNOSTIC_${field}=$item"}
   }
  }
 } catch {Write-Host 'ACTUAL_X_DIAGNOSTIC=UNAVAILABLE'}
 try {
  $events=Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Service Control Manager';StartTime=(Get-Date).AddMinutes(-4);Id=7031,7034,7036,7023,7024} -MaxEvents 80 -ErrorAction Stop
  foreach($record in $events | Sort-Object TimeCreated){
   if($record.Properties.Count -gt 0 -and [string]$record.Properties[0].Value -in @('Proxy VPN','OracleProxyService')){
    $data=if($record.Properties.Count -gt 1 -and [string]$record.Properties[1].Value -match '^[a-zA-Z0-9 ]{1,40}$'){[string]$record.Properties[1].Value}else{'not_exported'}
    Write-Host "ACTUAL_X_SCM_EVENT=$($record.Id);UTC=$($record.TimeCreated.ToUniversalTime().ToString('HH:mm:ss'));DATA=$data"
   }
  }
 } catch {Write-Host 'ACTUAL_X_SCM_EVENTS=UNAVAILABLE'}
 try {
  $events=Get-WinEvent -FilterHashtable @{LogName='Application';Id=1026;StartTime=(Get-Date).AddMinutes(-4)} -MaxEvents 20 -ErrorAction Stop
  foreach($record in $events){
   $message=[string]$record.Message
   if($message.Contains('Proxy.Service.exe') -and $message -match 'Exception Info: ([A-Za-z0-9.]+Exception)'){
    Write-Host "ACTUAL_X_DOTNET_EXCEPTION=$($Matches[1])"
   }
  }
 } catch {Write-Host 'ACTUAL_X_DOTNET_EVENTS=UNAVAILABLE'}
}
function Print-ControlTimings([int]$Cycle){
 $toggle=Find-Control 'diagnostics-toggle'
 if($Cycle -eq 1){$toggle.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()}
 $button=Find-Control 'connection-diagnostics'
 if(!$button){throw 'LIVE_DIAGNOSTICS_BUTTON_UNAVAILABLE'}
 if(![ProxyGuiCloseButton]::PostMessage([IntPtr]$button.Current.NativeWindowHandle,0x00F5,[IntPtr]::Zero,[IntPtr]::Zero)){throw 'LIVE_DIAGNOSTICS_OPEN_FAILED'}
 $watch=[Diagnostics.Stopwatch]::StartNew();$report=$null
 while(!$report -and $watch.Elapsed.TotalSeconds -lt 5){
  $condition=New-Object Windows.Automation.AndCondition(
   (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty,$gui.Id)),
   (New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty,'diagnostic-report')))
  $report=[Windows.Automation.AutomationElement]::RootElement.FindFirst([Windows.Automation.TreeScope]::Descendants,$condition)
  if(!$report){Start-Sleep -Milliseconds 20}
 }
 if(!$report){throw 'LIVE_DIAGNOSTICS_REPORT_UNAVAILABLE'}
 $value=$report.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).Current.Value
 foreach($line in ($value -split "`r?`n")){
  if($line -match '^(control\.(service_ready_ms|attested_pipe_ms|response_ms)|ui_(queue_ms|attach_ms|response_ms|complete_ms)): ([0-9]+)$'){
   Write-Host "ACTUAL_GUI_CONTROL_${Cycle}_$($Matches[1])=$($Matches[4])"
  }
 }
 # Native text editing may sit inside a rounded frame. Find its owning
 # dialog Window, never assume that the immediate parent is a top-level HWND.
 $dialog=$report
 while($dialog -and $dialog.Current.ControlType -ne [Windows.Automation.ControlType]::Window){
  $dialog=[Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($dialog)
 }
 if(!$dialog -or $dialog.Current.ProcessId -ne $gui.Id -or $dialog.Current.NativeWindowHandle -eq $gui.MainWindowHandle.ToInt64()){throw 'LIVE_DIAGNOSTICS_OWNING_DIALOG_NOT_FOUND'}
 if(![ProxyGuiCloseButton]::PostMessage([IntPtr]$dialog.Current.NativeWindowHandle,0x0112,[IntPtr]0xF060,[IntPtr]::Zero)){throw 'LIVE_DIAGNOSTICS_CLOSE_FAILED'}
 $watch.Restart()
 while($watch.Elapsed.TotalSeconds -lt 5){
  if(![Windows.Automation.AutomationElement]::RootElement.FindFirst([Windows.Automation.TreeScope]::Descendants,$condition)){
   Write-Host 'ACTUAL_DIAGNOSTICS_OWNING_DIALOG_CLOSED=PASS';return
  }
  Start-Sleep -Milliseconds 20
 }
 throw 'LIVE_DIAGNOSTICS_DIALOG_STILL_OPEN' 
}
$script:stage='initial-window' 
try {
 Await-Mode '已连接' $false
 foreach($cycle in 1..2){
  $script:stage="off-$cycle"
  $off=Find-Control 'disconnect';if(!$off -or !$off.Current.IsEnabled){throw 'LIVE_GUI_OFF_UNAVAILABLE'}
  $watch=[Diagnostics.Stopwatch]::StartNew();$off.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
  Await-Mode '已断开' $true
  $offMs=$watch.ElapsedMilliseconds
  Write-Host "ACTUAL_PROXY_GUI_UDP_OFF_AND_BACKEND_STOP_MS_${cycle}=$offMs"
  Write-Host "ACTUAL_PROXY_GUI_UDP_OFF_UNDER_1000MS_${cycle}=$($offMs -lt 1000)"
  $script:stage="on-$cycle"
  $on=Find-Control 'connect';if(!$on -or !$on.Current.IsEnabled){throw 'LIVE_GUI_ON_UNAVAILABLE'}
  $watch.Restart();$on.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
  Await-Mode '已连接' $false
  $onMs=$watch.ElapsedMilliseconds
  Write-Host "ACTUAL_PROXY_GUI_UDP_COLD_ON_AND_VERIFIED_DISPLAY_MS_${cycle}=$onMs"
  Write-Host "ACTUAL_PROXY_GUI_UDP_COLD_ON_UNDER_1000MS_${cycle}=$($onMs -lt 1000)"
  Print-ControlTimings $cycle
  & $SnapshotReader --live-udp-timing-snapshot
  if($LASTEXITCODE -ne 0){throw 'LIVE_TIMING_SNAPSHOT_FAILED'}
 }
 $script:stage='close-window'
 Service-Witness 'BEFORE'
 $gui.Refresh()
 if(![ProxyGuiCloseButton]::PostMessage($gui.MainWindowHandle,0x0112,[IntPtr]0xF060,[IntPtr]::Zero)){throw 'LIVE_GUI_CLOSE_BUTTON_MESSAGE_FAILED'}
 if(!$gui.WaitForExit(15000)){throw 'LIVE_GUI_X_DID_NOT_CLOSE'}
 $watch.Restart()
 while((Get-Service OracleProxyService).Status -ne 'Stopped' -and $watch.Elapsed.TotalSeconds -lt 15){Start-Sleep -Milliseconds 20}
 if((Get-Service OracleProxyService).Status -ne 'Stopped'){throw 'LIVE_GUI_X_LEFT_BACKEND'}
 Write-Host 'ACTUAL_PRODUCT_GUI_UDP_REPEATED_ON_OFF_DISPLAY_AND_NO_BACKGROUND=PASS'
} catch {
 Write-Host "ACTUAL_PROXY_GUI_FAILURE_STAGE=$script:stage"
 $code=if($_.Exception.Message -match '^[A-Z_]{1,80}$'){$_.Exception.Message}else{'TEST_RUNTIME_EXCEPTION'}
 Write-Host "ACTUAL_PROXY_GUI_FAILURE_CODE=$code"
 Exit-FailureWitness
 throw
} finally {if(!$gui.HasExited){$gui.Kill();$gui.WaitForExit()};$gui.Dispose()}
