@echo off

echo ===========================
echo %0 %*

setlocal enabledelayedexpansion

set "AD_PYTHON_HOME=%1"
if "%AD_PYTHON_HOME%" == "" (
  echo Invalid AD_PYTHON_HOME
  exit /b 1
)
if not exist "%AD_PYTHON_HOME%" (
  echo Not found %AD_PYTHON_HOME%
  exit /b 1  
)

set "PLAT=%2"
if "%PLAT%" == "" (
  echo Invalid PLAT
  exit /b 1
)

set "PYTHONPATH=%AD_PYTHON_HOME%;%AD_PYTHON_HOME%Scripts;%AD_PYTHON_HOME%DLLs;%AD_PYTHON_HOME%Lib\lib-tk;%AD_PYTHON_HOME%Lib\site-packages;"
echo PYTHONPATH=%PYTHONPATH%

set PATH=%VOL_ROOT%runtime\%PLAT%;%PYTHONPATH%;%PATH%;
echo PATH=%PATH%

@echo on
pyinstaller.exe --onedir -y --hidden-import=pkg_resources -i resources\ad.ico admemoryanalysis.py
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
xcopy /S /E /I %VOL_ROOT%dist\admemoryanalysis %VOL_ROOT%dist\%PLAT%\admemoryanalysis
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
if exist %VOL_ROOT%target\bin\vc100\Release.%PLAT%\winpmem.exe copy /y %VOL_ROOT%target\bin\vc100\Release.%PLAT%\winpmem.exe %VOL_ROOT%dist\%PLAT%\admemoryanalysis
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
xcopy /S /Y /D %VOL_ROOT%runtime\%PLAT%\* %VOL_ROOT%dist\%PLAT%\admemoryanalysis\*
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
rmdir /s /q %VOL_ROOT%build
rmdir /s /q %VOL_ROOT%dist\admemoryanalysis
@echo off

exit /b 0

:ERROR_OUT
echo Failed %0
exit /b 1
