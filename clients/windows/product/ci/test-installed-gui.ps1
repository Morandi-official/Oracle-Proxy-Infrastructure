param([Parameter(Mandatory=$true)][string]$Client)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'DISPOSABLE_HOSTED_WINDOWS_REQUIRED'}
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
$gui=Start-Process $Client -PassThru
try {
 $ready=$false;$watch=[Diagnostics.Stopwatch]::StartNew()
 while($watch.Elapsed.TotalSeconds -lt 60){
  $gui.Refresh();if($gui.HasExited){throw 'INSTALLED_GUI_EXITED_BEFORE_READY'}
  if($gui.MainWindowHandle -ne [IntPtr]::Zero){
   $window=[Windows.Automation.AutomationElement]::FromHandle($gui.MainWindowHandle)
   $condition=New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty,'login')
   $login=$window.FindFirst([Windows.Automation.TreeScope]::Descendants,$condition)
   if($login -and $login.Current.IsEnabled -and !$login.Current.IsOffscreen){$ready=$true;break}
  }
  Start-Sleep -Milliseconds 100
 }
 if(!$ready){throw 'INSTALLED_FIRST_GUI_LOGIN_NOT_READY'}
 $null=$gui.CloseMainWindow()
 if(!$gui.WaitForExit(15000)){throw 'INSTALLED_REAL_X_DID_NOT_CLOSE'}
 $stopped=$false;$watch.Restart()
 while($watch.Elapsed.TotalSeconds -lt 15){if((Get-Service OracleProxyService).Status -eq 'Stopped'){$stopped=$true;break};Start-Sleep -Milliseconds 100}
 if(!$stopped){throw 'INSTALLED_GUI_X_DID_NOT_STOP_BACKEND'}
 Write-Host 'ACTUAL_INSTALLED_GUI_LOGIN_READY_X_AND_BACKEND_STOP=PASS'
} finally {if(!$gui.HasExited){$gui.Kill();$gui.WaitForExit()};$gui.Dispose()}
