@echo off
rem Collect `dir /s` listings of every fixed drive for shallowtimeline.py (ShallowTimeline).
rem Run from an Administrator Command Prompt (not PowerShell).

rem High (S-1-16-12288) or System (S-1-16-16384) integrity = elevated.
set ELEV=NO
whoami /groups | findstr "S-1-16-12288 S-1-16-16384" >nul && set ELEV=yes
if %ELEV%==NO (
  echo WARNING: not running as Administrator.
  echo Many folders will be silently skipped. Press Ctrl+C to stop,
  echo then re-run from a Command Prompt opened with Run as administrator.
  pause
)

rem Change OUT to a USB drive (E:\collect) or share (\\server\share\HOST1).
set OUT=C:\collect
mkdir "%OUT%" 2>nul
pushd "%OUT%" || (echo Cannot open %OUT% & exit /b 1)
rem NTFS-compress the folder so less of the disk is overwritten.
compact /c /i /q "%OUT%" >nul 2>&1

rem Fixed drives to list. PowerShell's DriveType is language-neutral;
rem fsutil (English "Fixed Drive" text) is the fallback. The drive OUT is
rem on is skipped unless it is the system drive, so an external USB disk
rem that reports itself as fixed isn't listed.
set OUTDRV=%OUT:~0,2%
set DRIVES=
for /f %%d in ('powershell -NoProfile -Command "(Get-CimInstance Win32_LogicalDisk -Filter DriveType=3).DeviceID" 2^>nul') do call :adddrive %%d
if not defined DRIVES for %%d in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
  fsutil fsinfo drivetype %%d: 2>nul | find /i "Fixed" >nul && call :adddrive %%d:
)
if not defined DRIVES set DRIVES=%SystemDrive%
echo Drives to list:%DRIVES%

set K="HKCU\Control Panel\International"
>info.txt echo start %DATE% %TIME%
>>info.txt echo elevated=%ELEV%
>>info.txt whoami
>>info.txt hostname
>>info.txt tzutil /g
>>info.txt echo.
>>info.txt ver
>>info.txt w32tm /query /status 2>&1
>>info.txt reg query %K% /v sShortDate
>>info.txt reg query %K% /v sTimeFormat
>>info.txt fsutil fsinfo drives
>>info.txt echo listed=%DRIVES%

for %%d in (%DRIVES%) do call :listdrive %%d

>>info.txt echo end %DATE% %TIME%
tar -a -cf collect.zip *.txt
certutil -hashfile collect.zip SHA256
popd
echo DONE - send %OUT%\collect.zip and the SHA256 above
goto :eof

:adddrive
if /i "%~1"=="%OUTDRV%" if /i not "%~1"=="%SystemDrive%" goto :eof
set "DRIVES=%DRIVES% %~1"
goto :eof

:listdrive
set L=%~1
set L=%L:~0,1%
echo Listing %~1 modification times - this can take a while...
cmd /u /c "dir %~1\ /s /a /-c /t:w >dir_%L%_modified.txt 2>dir_%L%_errors.txt"
echo Listing %~1 creation times...
cmd /u /c "dir %~1\ /s /a /-c /t:c >dir_%L%_created.txt 2>nul"
goto :eof
