param([Parameter(Mandatory=$true)][string]$Client,[Parameter(Mandatory=$true)][string]$SnapshotReader,[switch]$CloseConnectedOnly)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_REF -ne 'refs/heads/main'){throw 'MAIN_DISPOSABLE_WINDOWS_REQUIRED'}
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ProxyGuiCloseButton {
 [DllImport("iphlpapi.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
 private static extern uint ConvertInterfaceAliasToLuid(string alias, out ulong luid);
 public static ulong AdapterLuid() {
  ulong luid; uint rc=ConvertInterfaceAliasToLuid("OracleProxy",out luid);
  if(rc==0 && luid!=0) return luid;
  if(rc==2 || rc==1168) return 0;
  throw new InvalidOperationException("LIVE_ADAPTER_QUERY_FAILED");
 }
 [DllImport("user32.dll", SetLastError=true)]
 public static extern bool PostMessage(IntPtr hwnd,uint message,IntPtr wParam,IntPtr lParam);
}
'@
$launch=[Diagnostics.Stopwatch]::StartNew()
$gui=Start-Process -FilePath $Client -PassThru
function Find-Control([string]$Id){
 $gui.Refresh();if($gui.HasExited){throw 'LIVE_GUI_EXITED'}
 if($gui.MainWindowHandle -eq [IntPtr]::Zero){return $null}
 $window=[Windows.Automation.AutomationElement]::FromHandle($gui.MainWindowHandle)
 $condition=New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty,$Id)
 return $window.FindFirst([Windows.Automation.TreeScope]::Descendants,$condition)
}
function Await-Mode([string]$Prefix,[bool]$RequireConnectButton){
 $watch=[Diagnostics.Stopwatch]::StartNew()
 $status=$null
 while($watch.Elapsed.TotalSeconds -lt 30){
  try {
   if(!$status){$status=Find-Control 'connection-status'}
   if($status -and !$status.Current.IsOffscreen -and $status.Current.Name.StartsWith($Prefix)){
    if(!$RequireConnectButton){return}
    $connect=Find-Control 'connect'
    if($connect -and $connect.Current.IsEnabled -and !$connect.Current.IsOffscreen){return $connect}
   }
  } catch [Windows.Automation.ElementNotAvailableException] {$status=$null}
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
 $button=$null
 $buttonDeadline=[Diagnostics.Stopwatch]::StartNew()
 while(!$button -and $buttonDeadline.Elapsed.TotalSeconds -lt 5){
  $button=Find-Control 'connection-diagnostics'
  if(!$button){Start-Sleep -Milliseconds 20}
 }
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
function Read-CoreWitness([bool]$Parked,[int]$TimedCycle=0) {
 $arg=if($Parked){'--live-udp-parked-snapshot'}else{'--live-udp-timing-snapshot'}
 $output=@(& $SnapshotReader $arg)
 $exitCode=$LASTEXITCODE
 foreach($line in $output){if($line.StartsWith('ACTUAL_')){Write-Host $line}}
 if($exitCode -ne 0){throw 'LIVE_ATTESTED_CORE_SNAPSHOT_FAILED'}
 $tag=if($Parked){'ACTUAL_PARKED_HOLDER_PID='}else{'ACTUAL_CONNECTED_HOLDER_PID='}
 $ids=@($output | Where-Object {$_.StartsWith($tag)})
 if($ids.Count -ne 1){throw 'LIVE_CORE_PID_UNAVAILABLE'}
 if($TimedCycle -gt 0){
  foreach($field in @('PREPARING','PARKED')){
   if(@($output -match "^ACTUAL_SERVICE_ADAPTER_${field}_AT_CLICK=(True|False)$").Count -ne 1){throw 'LIVE_GUI_CLICK_PREPARATION_STATE_UNAVAILABLE'}
  }
 }
 if($TimedCycle -gt 1 -and 'ACTUAL_SERVICE_ADAPTER_PARKED_AT_CLICK=True' -notin $output){throw 'LIVE_RECONNECT_DID_NOT_START_FROM_AUDITED_HOLDER'}
 return [uint32]($ids[0].Substring($tag.Length))
}
function Park-FailureWitness {
 try{
  $rows=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object Name -eq 'OracleProxy')
  Write-Host "ACTUAL_PARK_FAILURE_ADAPTER_COUNT=$($rows.Count)"
  if($rows.Count -eq 1){
   $idx=$rows[0].ifIndex
   $ip=@(Get-NetIPAddress -PolicyStore ActiveStore -ErrorAction Stop | Where-Object InterfaceIndex -eq $idx)
   $rt=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object InterfaceIndex -eq $idx)
   $servers=@(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object InterfaceIndex -eq $idx | ForEach-Object {$_.ServerAddresses} | Where-Object {$_})
   Write-Host "ACTUAL_PARK_FAILURE_IP_ROWS=$($ip.Count)"
   Write-Host "ACTUAL_PARK_FAILURE_ROUTE_ROWS=$($rt.Count)"
   Write-Host "ACTUAL_PARK_FAILURE_DNS_SERVERS=$($servers.Count)"
  }
 }catch{Write-Host 'ACTUAL_PARK_FAILURE_OS_WITNESS=UNAVAILABLE'}
}
function Assert-ParkedAdapter([uint32]$CoreId,[uint64]$ExpectedLuid) {
 $current=[ProxyGuiCloseButton]::AdapterLuid()
 if(!$current -or $current -ne $ExpectedLuid){throw 'LIVE_RETAINED_ADAPTER_REPLACED'}
 $adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {$_.Name -eq 'OracleProxy'})
 if($adapters.Count -ne 1 -or [guid]$adapters[0].InterfaceGuid -ne [guid]'62e2af98-7089-6f2c-246b-4a5960cfc978' -or $adapters[0].Status -eq 'Up'){throw 'LIVE_RETAINED_ADAPTER_NOT_DOWN'}
 $idx=$adapters[0].ifIndex
 $addresses=@(Get-NetIPAddress -PolicyStore ActiveStore -ErrorAction Stop | Where-Object InterfaceIndex -eq $idx)
 $routes=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object InterfaceIndex -eq $idx)
 $dns=@(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object InterfaceIndex -eq $idx)
 $servers=@($dns | ForEach-Object {$_.ServerAddresses} | Where-Object {$_})
 $dnsClient=@(Get-DnsClient -ErrorAction Stop | Where-Object InterfaceIndex -eq $idx)
 Write-Host "ACTUAL_PARKED_OS_IP_ROWS=$($addresses.Count)"
 Write-Host "ACTUAL_PARKED_OS_ROUTE_ROWS=$($routes.Count)"
 Write-Host "ACTUAL_PARKED_OS_DNS_SERVER_COUNT=$($servers.Count)"
 # The requested parked state has literally zero addresses and route rows.
 # Count Windows-generated link-local/multicast entries as well.
 if($addresses.Count -or $routes.Count){throw 'LIVE_RETAINED_ADAPTER_OS_ROWS_NOT_EMPTY'}
 if($servers.Count){throw 'LIVE_RETAINED_ADAPTER_DNS_NOT_EMPTY'}
 if(@($dnsClient | Where-Object { $_.ConnectionSpecificSuffix }).Count){throw 'LIVE_RETAINED_ADAPTER_SUFFIX_NOT_EMPTY'}
 if(@(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object OwningProcess -eq $CoreId).Count -or
    @(Get-NetTcpConnection -ErrorAction Stop | Where-Object OwningProcess -eq $CoreId).Count){throw 'LIVE_RETAINED_HOLDER_HAS_NETWORK_SOCKET'}
 if([ProxyGuiCloseButton]::AdapterLuid() -ne $ExpectedLuid){throw 'LIVE_RETAINED_ADAPTER_CHANGED_DURING_AUDIT'}
 Write-Host 'ACTUAL_PARKED_ADAPTER_NO_CONFIGURED_IP_ROUTE_DNS_OR_HOLDER_SOCKET=PASS'
}
$connectTargetMet=$true
$script:stage='initial-window'
try {
 $lastCore=0
 if($CloseConnectedOnly){
  Await-Mode '已连接' $false
  $lastCore=Read-CoreWitness $false
 }else{
  $on=Await-Mode '已断开' $true
  $retainedCore=0
  $retainedLuid=[uint64]0
  foreach($cycle in 1..3){
   $script:stage="on-$cycle"
   # This single native lookup records whether regular startup already
   # created the adapter. Never wait for or induce preparation before timing.
   $before=[ProxyGuiCloseButton]::AdapterLuid()
   if($cycle -gt 1 -and $before -ne $retainedLuid){throw 'LIVE_RECONNECT_LOST_RETAINED_ADAPTER'}
   $kind=if($cycle -eq 1){'FIRST'}else{'RETAINED'}
   $watch=[Diagnostics.Stopwatch]::StartNew()
   $on.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
   Await-Mode '已连接' $false
   $onMs=$watch.ElapsedMilliseconds
   if($cycle -eq 1){
    Write-Host "ACTUAL_FIRST_CLICK_ADAPTER_PRESENT=$($before -ne 0)"
    Write-Host "ACTUAL_FRESH_WINDOW_LAUNCH_TO_VERIFIED_DISPLAY_MS=$($launch.ElapsedMilliseconds)"
   }
   Write-Host "ACTUAL_PROXY_GUI_UDP_${kind}_ON_AND_VERIFIED_DISPLAY_MS_${cycle}=$onMs"
   if($onMs -ge 1000){$connectTargetMet=$false}
   Print-ControlTimings $cycle
   $lastCore=Read-CoreWitness $false $cycle
   $activeLuid=[ProxyGuiCloseButton]::AdapterLuid()
   if(!$activeLuid -or ($cycle -gt 1 -and ($activeLuid -ne $retainedLuid -or $lastCore -ne $retainedCore))){throw 'LIVE_RECONNECT_DID_NOT_REUSE_HOLDER_AND_ADAPTER'}
   $script:stage="off-$cycle"
   $off=Find-Control 'disconnect'
   if($off -and $off.Current.IsOffscreen){
    $nav=Find-Control 'navigate-connection'
    if(!$nav){throw 'LIVE_GUI_CONNECTION_NAVIGATION_MISSING'}
    $nav.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
    $off=Find-Control 'disconnect'
   }
   if(!$off -or !$off.Current.IsEnabled -or $off.Current.IsOffscreen){throw 'LIVE_GUI_OFF_UNAVAILABLE'}
   $watch.Restart()
   $off.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
   $on=Await-Mode '已断开' $true
   Write-Host "ACTUAL_PROXY_GUI_UDP_OFF_AND_DIRECT_DISPLAY_MS_${cycle}=$($watch.ElapsedMilliseconds)"
   $retainedCore=Read-CoreWitness $true
   if($retainedCore -ne $lastCore){throw 'LIVE_GUI_OFF_REPLACED_HOLDER'}
   Assert-ParkedAdapter $retainedCore $activeLuid
   $retainedLuid=$activeLuid
  }
 }
 $script:stage='close-window'
 Service-Witness 'BEFORE'
 $gui.Refresh()
 if(![ProxyGuiCloseButton]::PostMessage($gui.MainWindowHandle,0x0112,[IntPtr]0xF060,[IntPtr]::Zero)){throw 'LIVE_GUI_CLOSE_BUTTON_MESSAGE_FAILED'}
 if(!$gui.WaitForExit(15000)){throw 'LIVE_GUI_X_DID_NOT_CLOSE'}
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while((Get-Service OracleProxyService).Status -ne 'Stopped' -and $watch.Elapsed.TotalSeconds -lt 15){Start-Sleep -Milliseconds 20}
 if((Get-Service OracleProxyService).Status -ne 'Stopped'){throw 'LIVE_GUI_X_LEFT_BACKEND'}
 if([ProxyGuiCloseButton]::AdapterLuid() -ne 0 -or @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
  $_.Name -eq 'OracleProxy' -or [guid]$_.InterfaceGuid -eq [guid]'62e2af98-7089-6f2c-246b-4a5960cfc978'
 }).Count){throw 'LIVE_GUI_X_LEFT_ADAPTER'}
 if(@(Get-Process -ErrorAction Stop | Where-Object {$_.Id -eq $lastCore -or $_.ProcessName -eq 'Proxy.Core'}).Count){throw 'LIVE_GUI_X_LEFT_HOLDER'}
 if(!$connectTargetMet){throw 'LIVE_GUI_VERIFIED_CONNECT_OVER_TARGET'}
 Write-Host 'ACTUAL_PRODUCT_GUI_CLOSED_WITHOUT_SERVICE_HOLDER_OR_ADAPTER=PASS'
} catch {
 Park-FailureWitness
 Write-Host "ACTUAL_PROXY_GUI_FAILURE_STAGE=$script:stage"
 $code=if($_.Exception.Message -match '^[A-Z_]{1,80}$'){$_.Exception.Message}else{'TEST_RUNTIME_EXCEPTION'}
 Write-Host "ACTUAL_PROXY_GUI_FAILURE_CODE=$code"
 Exit-FailureWitness
 throw
} finally {if(!$gui.HasExited){$gui.Kill();$gui.WaitForExit()};$gui.Dispose()}
