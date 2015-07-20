@echo off

echo ===========================
echo %0 %*

setlocal enabledelayedexpansion

set "VOL_ROOT=%~dp0"

if "%AD_PYTHON_HOME_32%" == "" set "AD_PYTHON_HOME_32=c:\python27.32\"
if "%AD_PYTHON_HOME_64%" == "" set "AD_PYTHON_HOME_64=c:\python27\"

pushd "%VOL_ROOT%"

if "%SKIP_DRIVER_BUILD%" == "1" (
  echo SKIP_DRIVER_BUILD=%SKIP_DRIVER_BUILD%
  echo Skipped winpmem and driver builds
) else if exist "C:\WINDDK\7600.16385.1" (
  call "%~dp0tools\windows\winpmem\bld.bat" chk -cZ
  if errorlevel 1 goto :ERROR_OUT

  call "%~dp0tools\windows\winpmem\bld.bat" fre -cZ
  if errorlevel 1 goto :ERROR_OUT
  
  @echo on
  call "%~dp0target\dependency\tools\buildsln.bat" "%~dp0rekall.sln"
  @echo off
  if errorlevel 1 goto :ERROR_OUT
) else (
  echo ------------------------------------
  echo Rekall drivers will not be built and included
  echo To build rekall drivers please copy \\devshare\Devshare\rsharma\WinDDK\7600.16385.1 to your C:\WINDDK\7600.16385.1
  echo And manually import TestADDrivers3.pfx to TestADDriversStore
  echo ------------------------------------
)
rmdir /s /q %~dp0target\..\dist

call tools\Installers\winbuild.bat %AD_PYTHON_HOME_64% x64
if errorlevel 1 goto :ERROR_OUT

call tools\Installers\winbuild.bat %AD_PYTHON_HOME_32% Win32
if errorlevel 1 goto :ERROR_OUT

echo.
echo admemoryanalysis was successfully built
echo.

exit /b 0

:ERROR_OUT
echo Failed %0
exit /b 1