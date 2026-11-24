#ifndef BundleDir
  #error BundleDir is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif
#ifndef ProductVersion
  #error ProductVersion is required
#endif

[Setup]
AppId={{2A208744-D1F3-46FD-88FB-1845663512AE}
AppName=Oracle Proxy
AppVersion={#ProductVersion}
AppPublisher=Morandi
AppPublisherURL=https://github.com/Morandi-official/Oracle-Proxy-Infrastructure
AppSupportURL=https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/issues
VersionInfoVersion={#ProductVersion}.0
VersionInfoDescription=Oracle Proxy Windows Setup
DefaultDirName={autopf}\OracleProxyTailscale
DisableDirPage=yes
UsePreviousAppDir=no
DefaultGroupName=Oracle Proxy
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.19041
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
OutputDir={#OutputDir}
OutputBaseFilename=Proxy-{#ProductVersion}-win-x64-setup
LicenseFile={#BundleDir}\licenses\OracleProxy-GPL-3.0.txt
UninstallDisplayIcon={app}\Proxy.exe
CloseApplications=yes
CloseApplicationsFilter=Proxy.exe
RestartApplications=no
SetupLogging=yes

[Files]
Source: "{#BundleDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"; Flags: unchecked

[Icons]
Name: "{group}\Oracle Proxy"; Filename: "{app}\Proxy.exe"
Name: "{autodesktop}\Oracle Proxy"; Filename: "{app}\Proxy.exe"; Tasks: desktopicon

[Code]
function GetWindowsFileAttributes(const Name: String): LongWord;
  external 'GetFileAttributesW@kernel32.dll stdcall';

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Target: String;
  Attributes: LongWord;
begin
  Result := '';
  Target := ExpandConstant('{app}');
  if CompareText(Target, ExpandConstant('{autopf}\OracleProxyTailscale')) <> 0 then begin
    Result := 'The protected default installation directory is required.';
    Exit;
  end;
  Attributes := GetWindowsFileAttributes(Target);
  if (Attributes <> $FFFFFFFF) and ((Attributes and $400) <> 0) then
    Result := 'A linked installation directory cannot be used.';
end;
