@echo off
setlocal

rem ---- Input params ----
rem %1 = username
rem %2 = password
rem %3 = groupID
rem %4 = artifactID
rem %5 = code line (trunk or branch name)
rem %6 = group exclusions Format = groupA+groupB+...
rem %7 = component exclusions Format = componentA+componentB+...

echo Checking for all version clashes following optionals in %3.%4 in the %5 code line...

set "pw=%2"
set "pw=%pw:$=`$%"

set "groupExcludes=%6"
set "groupExcludes=%groupExcludes:~1,-1%"

set "compExcludes=%7"
set "compExcludes=%compExcludes:~1,-1%"

start /wait powershell.exe -NonInteractive -ExecutionPolicy RemoteSigned %CD%\target\dependency\tools\VersionCheckAllMismatches.ps1 -domainUser %1 -domainPassword %pw% -groupID %3 -artifactID %4 -codeline %5 -groupExclusions %groupExcludes% -componentExclusions %compExcludes%

set "errorThrown=%ERRORLEVEL%"

type output.txt

if %errorThrown% NEQ 0 exit /b 1
exit /b 0