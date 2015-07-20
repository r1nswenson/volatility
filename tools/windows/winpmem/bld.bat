@echo off

echo ===========================
echo %0 %*

setlocal enabledelayedexpansion

pushd "%~dp0"

if "%W7BASE%" == "" set "W7BASE=C:\WINDDK\7600.16385.1"
if not exist "%W7BASE%" (
  echo W7BASE=%W7BASE% not found
  goto :ERROR_OUT
)

if "%1" == "chk" set "PROJECTTYPE=chk"
if "%1" == "fre" set "PROJECTTYPE=fre"
if "%2" == "-Z" set "BUILDCOMMAND=-Z"
if "%2" == "-cZ" set "BUILDCOMMAND=-cZ"

if "%PROJECTTYPE%" == "" goto :USAGE
if "%BUILDCOMMAND%" == "" goto :USAGE

call ddkbuild.cmd -W7NET %PROJECTTYPE% . %BUILDCOMMAND%
if errorlevel 1 goto :ERROR_OUT

call :SIGN "obj%PROJECTTYPE%_wnet_x86\i386"
if errorlevel 1 goto :ERROR_OUT

call ddkbuild.cmd -W7NETX64 %PROJECTTYPE% . %BUILDCOMMAND%
if errorlevel 1 goto :ERROR_OUT

call :SIGN "obj%PROJECTTYPE%_wnet_amd64\amd64"
if errorlevel 1 goto :ERROR_OUT

exit /b 0

:USAGE
echo Usage:
echo.
echo %0 chk/fre -Z/-cZ
echo.
echo To enable test signing 
echo.
echo 1. run %~dp0CreateTestADDriversStore.bat
echo.
echo 2. manually import %~dp0TestADDrivers3.pfx to TestADDriversStore
exit /b 1

:ERROR_OUT
echo Failed %0
exit /b 1

:SIGN
echo ---------------
echo %0 %*
setlocal enabledelayedexpansion
pushd "%1"
echo %CD%

if defined BUILD_PASS if defined BUILD_USER (set BUILD_CREDS=true)


if "%BUILD_CREDS%" == "true" ( 
  @echo "%~dp0..\..\..\target\dependency\tools\CM\Signing\SigningTool.exe" "%~dp0\%*\winpmem.sys"
  "%~dp0..\..\..\target\dependency\tools\CM\Signing\SigningTool.exe" "%~dp0\%*\winpmem.sys"
) else (
  echo Signing using testsign certificate
  @echo on
  "%~dp0SignTool.exe" sign /s TestADDriversStore winpmem.sys
  @echo off
  exit /b 0
)
goto :EOF
