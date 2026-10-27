#ifndef PayloadDir
  #error PayloadDir must be the verified portable archive staging directory
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif
#ifndef ProductVersion
  #error ProductVersion is required
#endif
#ifndef VersionNumbers
  #error VersionNumbers is required
#endif
#ifndef ArtifactStem
  #error ArtifactStem is required
#endif

[Setup]
AppId={{26C03D94-CA79-4A48-BC2C-F45BD14C69F5}
AppName=Oracle Proxy
AppVersion={#ProductVersion}
AppPublisher=Morandi
AppPublisherURL=https://github.com/Morandi-official/Oracle-Proxy-Infrastructure
AppSupportURL=https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/issues
VersionInfoVersion={#VersionNumbers}
VersionInfoDescription=Oracle Proxy Windows Setup
DefaultDirName={autopf}\OracleProxyDesktop
DisableDirPage=yes
UsePreviousAppDir=no
DefaultGroupName=Oracle Proxy
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.17763
WizardStyle=modern
DisableWelcomePage=no
Compression=lzma2
SolidCompression=yes
OutputDir={#OutputDir}
OutputBaseFilename={#ArtifactStem}-setup
LicenseFile={#PayloadDir}\licenses\OracleProxy-GPL-3.0.txt
InfoBeforeFile={#PayloadDir}\请先阅读.txt
UninstallDisplayIcon={app}\OracleProxy.exe
CloseApplications=yes
CloseApplicationsFilter=OracleProxy.exe
RestartApplications=no
SetupLogging=yes
SignedUninstaller=no

[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "{#PayloadDir}\OracleProxy.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\OracleProxy.Core.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\OracleProxy.Guard.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\BUILD.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\SHA256SUMS.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\请先阅读.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Oracle Proxy"; Filename: "{app}\OracleProxy.exe"
Name: "{group}\Uninstall Oracle Proxy"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Oracle Proxy"; Filename: "{app}\OracleProxy.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\OracleProxy.exe"; Description: "Open Oracle Proxy"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Messages]
WelcomeLabel1=安装 Oracle Proxy
WelcomeLabel2=安装独立客户端和 VPN 系统服务。日常启动客户端无需管理员权限。%n%n安装版与便携版共用同一个系统服务；卸载会移除共用服务和本机接入信息，但不会删除服务器上的账号或设备记录。%n%n升级保留本机账号与设备信息。请先保存其他工作并关闭旧客户端窗口。
ConfirmUninstall=卸载 Oracle Proxy 将断开 VPN、恢复直连，并移除安装版及共用的系统服务与本机接入信息。便携版也需重新安装服务后才能使用。%n%n确定继续？

[Code]
var
  ServiceReady: Boolean;

function SafeSid(const Value: String): Boolean;
var
  I: Integer;
begin
  Result := (Length(Value) > 6) and (Copy(Value, 1, 4) = 'S-1-');
  for I := 5 to Length(Value) do
    if not (((Value[I] >= '0') and (Value[I] <= '9')) or (Value[I] = '-')) then
      Result := False;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  OwnerSid, Arguments: String;
  ExitCode: Integer;
begin
  Result := '';
  { Never permit a command-line /DIR to make an elevated uninstaller run a
    later user-writable client binary. The desktop directory is fixed. }
  if CompareText(ExpandConstant('{app}'), ExpandConstant('{autopf}\OracleProxyDesktop')) <> 0 then begin
    Result := 'The protected default installation directory is required.';
    Exit;
  end;
  if ServiceReady then Exit;
  ExtractTemporaryFile('OracleProxy.exe');
  ExtractTemporaryFile('OracleProxy.Core.exe');
  ExtractTemporaryFile('OracleProxy.Guard.dll');
  Arguments := '--install-interactive';
  { Administrators may explicitly select an owner for unattended installation.
    This invokes the same existing fixed --install SID boundary, not a shell. }
  OwnerSid := ExpandConstant('{param:OwnerSid|}');
  if OwnerSid <> '' then begin
    if not SafeSid(OwnerSid) then begin
      Result := 'A valid Windows owner SID is required.';
      Exit;
    end;
    Arguments := '--install ' + OwnerSid;
  end;
  if not Exec(ExpandConstant('{tmp}\OracleProxy.exe'), Arguments, ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then begin
    Result := 'The VPN system service could not be installed. No desktop files were changed.';
    Exit;
  end;
  if ExitCode <> 0 then begin
    Result := 'The VPN system service did not pass installation checks. Existing protection and account state were retained. Close the old client, then retry Setup; if recovery is required, use the existing client recovery action.';
    Exit;
  end;
  ServiceReady := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ExitCode: Integer;
begin
  if CurUninstallStep <> usUninstall then Exit;
  { This event runs after confirmation and before any logged files are removed.
    Inno treats an exception at usUninstall as fatal, preserving the UI if the
    product cannot safely clear its own guard/service. No sc.exe or shell. }
  if RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\OracleProxyService') then begin
    if not Exec(ExpandConstant('{app}\OracleProxy.exe'), '--uninstall', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then
      RaiseException('Safe VPN service removal could not start. No desktop files were removed.');
    if ExitCode <> 0 then
      RaiseException('VPN protection could not be safely removed. Use the client recovery action and retry uninstall. No desktop files were removed.');
  end else if DirExists(ExpandConstant('{autopf}\OracleProxy')) then
    RaiseException('The shared service is missing but protected product files remain. Repair the installation before uninstalling. No desktop files were removed.');
end;
