Unicode true
SetCompressor /FINAL /SOLID lzma

!define PRODUCT_NAME "FAST"
!define PRODUCT_VERSION "1.0"
!define PRODUCT_PUBLISHER "Fileless Attack Solution Team"
!define PRODUCT_WEB_SITE ""
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\FAST\fast-monitor.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

!include "MUI.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"

!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
;!insertmacro MUI_PAGE_LICENSE "C:\path\to\license\YourSoftwareLicense.txt"
; Directory page
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
;!define MUI_FINISHPAGE_RUN "$INSTDIR\fast-monitor.exe"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Korean"

; MUI end -------------------------------

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "fast-setup.exe"
InstallDir "$PROGRAMFILES\FAST"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

Function CheckVCRedist_x86
   Push $R9
   ClearErrors
   ReadRegDword $R9 HKLM "Software\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\X86" "Installed"
   IfErrors 0 VSRedistInstalled
      StrCpy $R9 "No"
   VSRedistInstalled:
      Exch $R9
FunctionEnd

Function CheckVCRedist_x64
   Push $R9
   ClearErrors
   ReadRegDword $R9 HKLM "Software\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\X64" "Installed"
   IfErrors 0 VSRedistInstalled
      StrCpy $R9 "No"
   VSRedistInstalled:
      Exch $R9
FunctionEnd

!define MSVC_VER "14.28.29325"

Function CheckUseFile
ClearErrors
   SetOutPath "$INSTDIR"
   SetOverwrite try
   File "fast-monitor\x64\Release\fast-monitor.exe"
   File "fast-monitor\Win32\Release\FAST-DLL-32.dll"
   File "fast-monitor\x64\Release\FAST-DLL-64.dll"
${If} ${Errors}
      MessageBox MB_ICONINFORMATION|MB_OK "Program is already running." IDOK true
      true:
         Quit
${Endif}
FunctionEnd

Function .onInit
   ${If} ${RunningX64}
      DetailPrint "Installer running on 64-bit host"
      ; disable registry redirection (enable access to 64-bit portion of registry)
      SetRegView 64
      ; change install dir
      StrCpy $INSTDIR "$PROGRAMFILES64\FAST"
   ${EndIf}
FunctionEnd

Section "Visual Studio Runtime"
   SetOutPath "$INSTDIR"
   File "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Redist\MSVC\${MSVC_VER}\vcredist_x86.exe"
   File "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Redist\MSVC\${MSVC_VER}\vcredist_x64.exe"

   Call CheckVCRedist_x64
      Pop $R9
      StrCmp $R9 "No" 0 +3
      MessageBox MB_OK|MB_ICONSTOP "Install Visual C++ 2008 Redistributable 64 bit to run the program."
      ExecWait "$INSTDIR\vcredist_x64.exe"
      Delete "$INSTDIR\vcredist_x64.exe"

   Call CheckVCRedist_x86
      Pop $R9
      StrCmp $R9 "No" 0 +3
      MessageBox MB_OK|MB_ICONSTOP "Install Visual C++ 2008 Redistributable 32 bit to run the program."
      ExecWait "$INSTDIR\vcredist_x86.exe"
      Delete "$INSTDIR\vcredist_x86.exe"
SectionEnd

Section "MainSection" SEC01
   SetShellVarContext all
   Call CheckUseFile
   
   SetOutPath "$INSTDIR"
   SetOverwrite on
   File "fast-monitor\x64\Release\fast-monitor.exe"
   File "fast-monitor\Win32\Release\fast-monitor-win32.exe"
   File "fast-monitor\Win32\Release\FAST-DLL-32.dll"
   File "fast-monitor\x64\Release\FAST-DLL-64.dll"
   File "fast-monitor\x64\Release\hook-dll.exe"
   File "SDL2-devel-2.0.12-VC\SDL2-2.0.12\lib\x64\SDL2.dll"
   File "mysql-8.0.22-winx64\lib\libmysql.dll"
   File "fast-monitor\fast-monitor\libcrypto-1_1-x64.dll"
   File "fast-monitor\fast-monitor\libssl-1_1-x64.dll"
   File "fast-monitor\fast-monitor\DumpIt.exe"
SectionEnd

Section -AdditionalIcons
   CreateDirectory "$SMPROGRAMS\FAST"
   CreateShortCut "$SMPROGRAMS\FAST\Uninstall.lnk" "$INSTDIR\uninst.exe"
   CreateShortCut "$SMPROGRAMS\FAST\FAST Monitor.lnk" "$INSTDIR\fast-monitor.exe"
   CreateShortCut "$SMPROGRAMS\FAST\FAST Monitor (x86 console).lnk" "$INSTDIR\fast-monitor-win32.exe"
   CreateShortCut "$DESKTOP\FAST Monitor.lnk" "$INSTDIR\fast-monitor.exe"
SectionEnd

Section -Post
   WriteUninstaller "$INSTDIR\uninst.exe"
   WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
   WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
   WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
   WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
   WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
SectionEnd

Function un.onUninstSuccess
   HideWindow
   MessageBox MB_ICONINFORMATION|MB_OK "$(^Name) has been completely removed."
FunctionEnd

Function un.onInit
   MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to delete $(^Name)?" IDYES +2
   Abort
FunctionEnd

Section Uninstall
   SetShellVarContext all
   Delete "$INSTDIR\*.*"
   Delete "$DESKTOP\FAST Monitor.lnk"
   Delete "$SMPROGRAMS\FAST\Uninstall.lnk"
   Delete "$SMPROGRAMS\FAST\FAST Monitor.lnk"
   Delete "$SMPROGRAMS\FAST\FAST Monitor (x86 console).lnk"
   RMDir "$SMPROGRAMS\FAST"
   RMDir "$INSTDIR"
   DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
   SetAutoClose true
SectionEnd
