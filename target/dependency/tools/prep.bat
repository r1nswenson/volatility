@echo off

rem Get path of this batch file.
set "toolspath=%~dp0"

rem Set WGETRC and add toolspath to path
set "WGETRC=%toolspath%\.wgetrc"
path %toolspath%;%SystemRoot%;%SystemRoot%\system32

if "%1"=="copyonly" goto setup_copy_only

rem Make sure we are in the build directory.
if not exist pom.xml exit /b 1
cd target

set INCLUDE=
set LIB=

if not exist work md work
cd work

rem locate the VS2010 VC dir.
if defined VC10DIR (
 if exist "%VC10DIR%bin" goto havevcdir
)
set "VC10DIR=%ProgramFiles(x86)%\Microsoft Visual Studio 10.0\VC\"
if exist "%VC10DIR%bin" goto havevcdir
set "VC10DIR=%ProgramFiles%\Microsoft Visual Studio 10.0\VC\"
if exist "%VC10DIR%bin" goto havevcdir
for %%p in ("%VS100COMNTOOLS%..\..\VC\") do set "VC10DIR=%%~p"
if exist "%VC10DIR%bin" goto havevcdir

:novcdir
echo There is no Visual Studio 10 installed.
exit /b 2

:havevcdir
rem determine if and which x64 compiler is available.
set "VC10X64ENVBAT=%VC10DIR%bin\amd64\vcvars64.bat"
if exist "%VC10X64ENVBAT%" goto x64batexists
set "VC10X64ENVBAT=%VC10DIR%bin\x86_amd64\vcvarsx86_amd64.bat"
if exist "%VC10X64ENVBAT%" goto x64batexists
echo There is no VC10 x64 compiler available.

:x64batexists
rem locate the x32 env batch file.
set "VC10X32ENVBAT=%VC10DIR%bin\vcvars32.bat"
if exist "%VC10X32ENVBAT%" goto x32batexists
set "VC10DIR="
goto novcdir

:setup_copy_only
echo Only setting up copy env vars.
:x32batexists
rem FOR %%A in (robocopy.exe) DO (if exist %%~dpnx$PATH:A set "ROBOCOPY_AVAILABLE=1")
rem if "%ROBOCOPY_AVAILABLE%" == "" (
 set "USING_XCOPY=1"
 set "COPY=xcopy /D /Y /I"
 set "COPYDIR=xcopy /D /Y /I /S"
rem ) else (
rem  set "USING_ROBOCOPY=1"
rem  set ROBOCOPY_AVAILABLE=
rem  set "COPY=robocopy /R:3 /R:5 /NFL"
rem  set "COPYDIR=robocopy /DCOPY:T /R:3 /R:5 /NFL /S"
rem )
echo Environment set up correctly.
@echo on
