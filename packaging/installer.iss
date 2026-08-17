; Instalador de pruebas de VPN Manager.
;
; SIN FIRMAR. Windows y SmartScreen avisaran al ejecutarlo, y hacen bien: este
; .exe sirve para probar en una VM, no para repartirlo por la oficina. El
; empaquetado para Intune vendra cuando exista el certificado de firma.
;
; Se compila con:  ISCC packaging\installer.iss

#define AppName "VPN Manager"
#define AppVersion GetEnv("VPNMGR_VERSION")
#if AppVersion == ""
  #define AppVersion "0.1.0-dev"
#endif

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName={autopf}\VpnManager
DefaultGroupName={#AppName}
OutputDir=..\dist\installer
OutputBaseFilename=VpnManager-{#AppVersion}-setup
Compression=lzma2
SolidCompression=yes
; Necesita administrador: crea un servicio y escribe en Program Files.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
WizardStyle=modern

[Files]
; Dos bundles independientes: cada .exe con su runtime. Se paga espacio a
; cambio de que uno no pueda dejar al otro sin arrancar.
Source: "..\dist\vpnmgr-svc\*"; DestDir: "{app}\svc"; Flags: recursesubdirs ignoreversion
Source: "..\dist\vpnmgr-ui\*"; DestDir: "{app}\ui"; Flags: recursesubdirs ignoreversion

; Catalogo de ejemplo. No pisa el que ya haya: si alguien ya ha configurado
; sus perfiles, una reinstalacion no se los puede llevar por delante.
Source: "..\docs\profiles.example.json"; DestDir: "{commonappdata}\VpnManager"; \
    DestName: "profiles.json"; Flags: onlyifdoesntexist

[Dirs]
; Escritura solo para Administradores y SYSTEM. Es la mitad de la proteccion
; del catalogo: si un usuario sin privilegios puede escribir ahi, elige que
; binario ejecuta el servicio como SYSTEM.
Name: "{commonappdata}\VpnManager"; Permissions: admins-full system-full users-readexec

[Icons]
Name: "{group}\VPN Manager"; Filename: "{app}\ui\vpnmgr-ui.exe"
Name: "{userstartup}\VPN Manager"; Filename: "{app}\ui\vpnmgr-ui.exe"; Tasks: autostart

[Tasks]
Name: autostart; Description: "Arrancar la bandeja al iniciar sesion"; GroupDescription: "Inicio:"
Name: installservice; Description: "Instalar el servicio (si no, se arranca a mano en consola)"; \
    GroupDescription: "Servicio:"
Name: allowunsigned; Description: \
    "PRUEBAS: aceptar el catalogo sin firma. NO usar en un equipo de la empresa."; \
    GroupDescription: "Servicio:"; Flags: unchecked

[Run]
; Con --allow-unsigned-catalog el catalogo deja de estar protegido por una
; firma. Es lo unico que permite probar sin certificado, y por eso va como una
; casilla aparte, desmarcada y con el aviso escrito.
; El Administrador de servicios arranca el .exe sin argumentos, asi que la
; opcion de catalogo sin firma no puede ir en binPath: se deja marcada con un
; fichero junto al catalogo, en un directorio donde solo escriben los
; administradores.
Filename: "{sys}\sc.exe"; \
    Parameters: "create VpnManagerSvc binPath= ""{app}\svc\vpnmgr-svc.exe"" start= auto DisplayName= ""VPN Manager"""; \
    Flags: runhidden; Tasks: installservice
Filename: "{sys}\sc.exe"; Parameters: "start VpnManagerSvc"; Flags: runhidden; Tasks: installservice

Filename: "{app}\ui\vpnmgr-ui.exe"; Description: "Abrir la bandeja"; Flags: postinstall nowait skipifsilent

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('allowunsigned') then
    SaveStringToFile(ExpandConstant('{commonappdata}\VpnManager\ALLOW_UNSIGNED_CATALOG'),
      'Solo pruebas. Con este fichero el catalogo no se verifica.' + #13#10, False);
end;

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop VpnManagerSvc"; Flags: runhidden; RunOnceId: "StopSvc"
Filename: "{sys}\sc.exe"; Parameters: "delete VpnManagerSvc"; Flags: runhidden; RunOnceId: "DelSvc"

[UninstallDelete]
; El catalogo no se borra: puede tener perfiles que costo configurar, y una
; desinstalacion para actualizar no deberia perderlos.
Type: filesandordirs; Name: "{app}"
