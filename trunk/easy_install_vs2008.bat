@echo off

::First install en_visual_studio_2008_professional_x86_dvd_x14-26326
::During install make sure to select custom and install 64 bit compilers;

::Then install python 32 to c:\python27.32 and 64 to c:\python27

::copy easy_install_vs2008.bat, adataCA.pem, ez_setup.py pywin32-219.win32-py2.7.exe, pywin32-219.win-amd64-py2.7.exe, 
::to c:\python27 adn c:\python27.32

:: Last run this script

setlocal enabledelayedexpansion

if "%AD_PYTHON_HOME_32%" == "" set "AD_PYTHON_HOME_32=c:\python27.32"
if "%AD_PYTHON_HOME_64%" == "" set "AD_PYTHON_HOME_64=c:\python27"

pushd "%~dp0"

if not exist adataCA.pem (
  echo adataCA.pem not found
  goto :ERROR_OUT
)

if not exist ez_setup.py (
  echo ez_setup.py not found
  goto :ERROR_OUT
)

if /i "%CD%" == "%AD_PYTHON_HOME_32%" (
  echo Detected x86 installation
  if not exist pywin32-219.win32-py2.7.exe (
    echo pywin32-219.win32-py2.7.exe not found
    goto :ERROR_OUT
  )
  if not exist yara-python-3.1.0.win32-py2.7.exe (
    echo yara-python-3.1.0.win32-py2.7.exe not found
    goto :ERROR_OUT
  )
  if not exist "%AD_PYTHON_HOME_32%" (
    echo %AD_PYTHON_HOME_32% not found
    goto :ERROR_OUT
  )
  set "PATH=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;%AD_PYTHON_HOME_32%;"
  call "C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" x86
  if errorlevel 1 goto :ERROR_OUT
) else (
  echo Detected amd64 installation
  if not exist pywin32-219.win-amd64-py2.7.exe (
    echo pywin32-219.win-amd64-py2.7.exe not found
    goto :ERROR_OUT
  )
  if not exist yara-python-3.1.0.win-amd64-py2.7.exe (
    echo yara-python-3.1.0.win-amd64-py2.7.exe not found
    goto :ERROR_OUT
  )
  if not exist C:\Python27 (
    echo C:\Python27 not found
    goto :ERROR_OUT
  )
  set "PATH=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\python27;"
  call "C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" amd64
  if errorlevel 1 goto :ERROR_OUT
)

echo VS90COMNTOOLS=%VS90COMNTOOLS%
echo PATH=%PATH%

@echo on
python ez_setup.py install > nul 2>&1
@echo off
if errorlevel 1 goto :ERROR_OUT

pushd "%~dp0"
copy /y adataCA.pem Scripts
if errorlevel 1 goto :ERROR_OUT

@echo on
python ez_setup.py install
@echo on
if errorlevel 1 goto :ERROR_OUT

pushd "%~dp0Scripts"
@echo on
easy_install argparse
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install PyYAML
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install pytz
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install protobuf
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install pycrypto
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install pyelftools
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install distorm3
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install acora
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install codegen
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install pefile
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install hexdump
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install Flask
@echo off
if errorlevel 1 goto :ERROR_OUT

@echo on
easy_install pyinstaller
@echo off
if errorlevel 1 goto :ERROR_OUT

pushd "%~dp0"

::dont know if still needed
::copy /y __init__.py Lib\site-packages\distorm3-3-py2.7.egg\distorm3
::if errorlevel 1 goto :ERROR_OUT

type nul > %AD_PYTHON_HOME_64%\lib\site-packages\google\__init__.py
type nul > %AD_PYTHON_HOME_32%\lib\site-packages\google\__init__.py

if /i "%CD%" == "%AD_PYTHON_HOME_32%" (
  pywin32-219.win32-py2.7.exe
  yara-python-3.1.0.win32-py2.7.exe
) else (
  pywin32-219.win-amd64-py2.7.exe
  yara-python-3.1.0.win-amd64-py2.7.exe
)

exit /b 0

:ERROR_OUT
echo Failed %0 %*
exit /b 1
