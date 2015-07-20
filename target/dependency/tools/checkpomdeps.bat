@echo off
setlocal

rem ---- Input params ----
rem %1, %2, %3, ... = POM filenames to be combined to check for version clashes.
echo Checking for version clashes in these poms: %*

rem Get folder of this batch file.
set "thisfolder=%~dp0"

rem Create temp folder for big pom...
set "pomdir=%TEMP%\bigpom_%RANDOM%%RANDOM%\"
mkdir "%pomdir%"
if %ERRORLEVEL% NEQ 0 (
	echo Error creating temp folder
	exit /b 1
)

rem Combine poms...
"%thisfolder%pomdeps.exe" %* > "%pomdir%pom.xml"
if %ERRORLEVEL% NEQ 0 (
	echo Error creating big pom
	exit /b 1
)

rem Check for version clashes in big pom...
cd /D "%pomdir%"
call mvn.bat -q addependency:check-versions
if %ERRORLEVEL% NEQ 0 (
	echo Version check failed
	exit /b 1
)

cd "%thisfolder%"
exit /b 0
