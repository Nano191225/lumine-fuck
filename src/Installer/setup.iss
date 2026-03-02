; LumineFuck Firewall - Inno Setup Script
; Requires Inno Setup 6.x+

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

#define AppName "LumineFuck Firewall"
#define AppPublisher "Nano191225"
#define AppExeName "LumineFuck.exe"
#define AppURL "https://github.com/Nano191225/lumine-fuck"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputDir=..\..\Output
OutputBaseFilename=LumineFuck-Setup-{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}
SetupIconFile=..\LumineFuck\Resources\app.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "japanese"; MessagesFile: "compiler:Languages\Japanese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startup"; Description: "Start automatically with Windows"; GroupDescription: "Startup:"

[Files]
; Published output (self-contained)
Source: "..\..\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Registry]
; Auto-start on login (if task selected)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
  ValueType: string; ValueName: "LumineFuck"; ValueData: """{app}\{#AppExeName}"""; \
  Flags: uninsdeletevalue; Tasks: startup

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; \
  Flags: nowait postinstall skipifsilent runascurrentuser

[Code]
// Check Npcap is installed before completing setup
function InitializeSetup(): Boolean;
var
  ErrorCode: Integer;
begin
  // Check via the Npcap Windows service key (not subject to WOW64 registry redirection)
  if not RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\npcap') then
  begin
    if MsgBox('Npcap is required for UDP traffic monitoring (same driver as Wireshark).' + #13#10 +
              'Click OK to open the Npcap download page, then re-run this installer after installing Npcap.',
              mbInformation, MB_OKCANCEL) = IDOK then
    begin
      ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
    end;
    Result := False;
    Exit;
  end;
  Result := True;
end;

// Clean up all LumineFW firewall rules on uninstall
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Exec('netsh', 'advfirewall firewall delete rule name="LumineFW_Block_TCP_IN"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('netsh', 'advfirewall firewall delete rule name="LumineFW_Block_TCP_OUT"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('netsh', 'advfirewall firewall delete rule name="LumineFW_Block_UDP_IN"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('netsh', 'advfirewall firewall delete rule name="LumineFW_Block_UDP_OUT"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
