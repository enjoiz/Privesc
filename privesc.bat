@echo off

setlocal EnableDelayedExpansion

REM if checks that takes much more time should be executed
set long=no

echo This batch needs accesschk.exe, Listdlls.exe, pipelist.exe from Sysinternals for best results.
echo.
echo System Information (use windows-exploit-suggester.py to check for local exploits):
echo.
systeminfo 2>NUL
systeminfo > systeminfo_for_suggester.txt
echo.
echo ----------------------------------------------------------------------------
echo.
echo Environment variables:
echo.
set 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Information about current user:
echo.
net user %USERNAME% 2>NUL
net user %USERNAME% /domain 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Available drives:
echo.
wmic logicaldisk get deviceid,volumename,description | more
echo.
echo ----------------------------------------------------------------------------
echo.
echo Network information:
echo.
ipconfig /all 2>NUL
echo.
route print 2>NUL
echo.
arp -A 2>NUL
echo.
netstat -ano 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Running processes:
echo.
tasklist /V 2>NUL
wmic process list | more
echo.
echo ----------------------------------------------------------------------------
echo.
echo Scheduled processes:
echo.
schtasks /query /fo LIST /v 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Installed software:
echo.
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall 2>NUL
dir "%PROGRAMFILES%" 2>NUL
dir "%ProgramFiles(x86)%" 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Startup programs:
echo.
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" 2>NUL
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>NUL
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>NUL
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>NUL
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Temp files:
echo.
dir "%TEMP%" 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Startup services:
echo.
net start 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Installed drivers:
echo.
driverquery 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Applied hotfixes:
echo.
wmic qfe get Caption,Description,HotFixID,InstalledOn |more
echo.
echo ----------------------------------------------------------------------------
echo.
echo Files that may contain Administrator password:
echo.
type C:\sysprep.inf 2>NUL
type C:\sysprep\sysprep.xml 2>NUL
type "%WINDIR%\Panther\Unattend\Unattended.xml" 2>NUL
type "%WINDIR%\Panther\Unattended.xml" 2>NUL
findstr /S cpassword \\127.0.0.1\sysvol\*.xml
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking AlwaysInstallElevated (install *.msi files as NT AUTHORITY\SYSTEM - exploit/windows/local/always_install_elevated):
echo.
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>NUL
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>NUL
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking permissions on services (changing BINARY_PATH_NAME - possible if SERVICE_CHANGE_CONFIG, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL):
echo It is also adviced to use Instrsrv.exe and Srvany.exe to try to create user defined service
echo.
for /f "tokens=2" %%x in ('sc query state^= all^|find /i "service_name"') do accesschk.exe -accepteula -ucqv %%x
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking permissions on services registy keys and subkeys (changing ImagePath value of a service):
accesschk.exe -accepteula -kvuqsw hklm\System\CurrentControlSet\services
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking BINARY_PATH_NAME for all services (if there is a space and path is not enclosed with quotes then it may be vulnerable - exploit/windows/local/trusted_service_path):
echo.
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME') do echo %%~s
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking file permissions of running services (File backdooring - exploit/windows/local/service_permissions):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
for /f "tokens=2 delims='='" %%x in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do (for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do cmd.exe /c icacls "%%z" ^| more)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking directory permissions of running services (DLL injection):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
for /f "tokens=2 delims='='" %%x in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	set tpath=%%~dpy
	cmd.exe /c icacls "!tpath:~,-1!" ^| more
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking file permissions of running processes (File backdooring - maybe the same files start automatically when Administrator logs in):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do cmd.exe /c icacls "%%z" ^| more)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking directory permissions of running processes (DLL injection):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	set tpath=%%~dpy
	cmd.exe /c icacls "!tpath:~,-1!" ^| more
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking named pipes permissions (it depends on what named pipe does with written data):
echo.
for /f "tokens=1" %%x in ('pipelist.exe') do (
	accesschk.exe -accepteula \pipe\%%x
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo List unsigned DLLs loaded by processes and their privileges (good to check also "not found" DLLs and registry keys using Procmon.exe):
echo.
for /f "tokens=2 delims=:" %%x in ('Listdlls.exe -u^|find /i "0x"^|find /i /v "system32"^|find /i /v "winsxs"') do (
	cmd.exe /c icacls "C:%%x" ^| more
)
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking system32 permissions misconfiguration (binaries that are good to backdoor - system32sethc.exe (Sticky Keys), system32utilman.exe):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
cmd.exe /c icacls "C:\Windows\system32" ^| more
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking startup directory permissions for all users (executing binaries with permissions of logged user):
echo https://technet.microsoft.com/pl-pl/library/cc753525(v=ws.10).aspx - shows permissions definition
echo.
cmd.exe /c icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" ^| more
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking all possibly exploitable services and their registries (eg. changing paths):
echo.
accesschk.exe -accepteula -uwcqv Users *
accesschk.exe -accepteula -uwcqv "Authenticated Users" *
accesschk.exe -accepteula -uwcqv Everyone *
accesschk.exe -accepteula -kvuqsw "Authenticated Users" hklm\System\CurrentControlSet\services
accesschk.exe -accepteula -kvuqsw "Users" hklm\System\CurrentControlSet\services
accesschk.exe -accepteula -kvuqsw "Everyone" hklm\System\CurrentControlSet\services
echo.
echo ----------------------------------------------------------------------------
echo.
echo Checking all possibly exploitable registries (eg. changing paths):
echo.
echo HKLM:
accesschk.exe -accepteula -kvuqsw "Authenticated Users" hklm
accesschk.exe -accepteula -kvuqsw "Users" hklm
accesschk.exe -accepteula -kvuqsw "Everyone" hklm
echo.
echo HKCU:
accesschk.exe -accepteula -kvuqsw "Authenticated Users" hkcu
accesschk.exe -accepteula -kvuqsw "Users" hkcu
accesschk.exe -accepteula -kvuqsw "Everyone" hkcu
echo.
echo HKU:
accesschk.exe -accepteula -kvuqsw "Authenticated Users" hku
accesschk.exe -accepteula -kvuqsw "Users" hku
accesschk.exe -accepteula -kvuqsw "Everyone" hku
echo.

if "%long%" == "yes" (
	echo ----------------------------------------------------------------------------
	echo.
	echo Weak file/directory permissions on all drives:
	echo.
	for /f %%x in ('wmic logicaldisk get name^| more') do (
		set tdrive=%%x
		if "!tdrive:~1,2!" == ":" (
			accesschk.exe -accepteula -uwdqs Users %%x
			accesschk.exe -accepteula -uwdqs "Authenticated Users" %%x
			accesschk.exe -accepteula -uwqs Users %%x\*.*
			accesschk.exe -accepteula -uwqs "Authenticated Users" %%x\*.*
		)
	)
	echo.
	echo ----------------------------------------------------------------------------
	echo.
	echo Looking for sensitive registry keys:
	echo.
	reg query HKLM /f pass /t REG_SZ /s
	reg query HKCU /f pass /t REG_SZ /s
	reg query HKLM /f pwd /t REG_SZ /s
	reg query HKCU /f pwd /t REG_SZ /s
	echo.
	echo ----------------------------------------------------------------------------
	echo.
	echo Looking for sensitive files:
	echo.
	for /f %%x in ('wmic logicaldisk get name^| more') do (
		set tdrive=%%x
		if "!tdrive:~1,2!" == ":" (
			%%x
			findstr /si pass *.xml *.ini *.txt *.cfg *.config
			findstr /si pwd *.xml *.ini *.txt *.cfg *.config
		)
	)
	echo.
)
