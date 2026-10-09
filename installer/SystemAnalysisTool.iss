; Compile after running build_windows.bat.
#define MyAppName "System Analysis Tool"
#define MyAppVersion "1.3.1"
#define MyAppPublisher "System Analysis Tool"
#define MyAppExeName "SystemAnalysisTool.exe"

[Setup]
AppId={{C72F3E11-7E9D-4AA0-AD3C-7AF30E6D4C12}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\System Analysis Tool
DefaultGroupName={#MyAppName}
OutputDir=..\installer-output
OutputBaseFilename=SystemAnalysisTool-Setup-1.3.1
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\SystemAnalysisTool\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: postinstall nowait skipifsilent
