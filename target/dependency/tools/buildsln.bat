@echo off
setlocal

rem ---- Input params ----
rem %1 = Solution Name
rem %2 = Platform (Win32, x64, all, or other)
rem %3 = Configuration (Release, Debug, all, or other)
rem %4 = Target (Build, Clean, Rebuild, or other)
rem %5 = maxcpucount (defaults to # of processors)

rem Get folder of this batch file.
set "thisfolder=%~dp0"

set "slnname=%~1"
if "%slnname%" == "" goto :fail
if not exist "%slnname%" (
	echo Solution %slnname% not found!
	goto :fail
)

set "platform=%~2"
set "config=%~3"
set "target=%~4"
set "maxcpucount=%~5"
if "%platform%" == "" set "platform=all"
if "%config%" == "" set "config=all"
if "%target%" == "" set "target=Build"

rem Call myself multiple times when config or platform is "all"...
set "failed=0"
if "%platform%" == "all" (
 call %0 "%slnname%" Win32 "%config%" "%target%" "%maxcpucount%" || set "failed=1"
 call %0 "%slnname%" x64 "%config%" "%target%" "%maxcpucount%" || set "failed=1"
)
if "%platform%" == "all" exit /b %failed%

if "%platform%" == "Win32AndAnyCPU" (
 call %0 "%slnname%" Win32 "%config%" "%target%" "%maxcpucount%" || set "failed=1"
 call %0 "%slnname%" "Any CPU" "%config%" "%target%" "%maxcpucount%" || set "failed=1"
)
if "%platform%" == "Win32AndAnyCPU" exit /b %failed%

if "%config%" == "all" (
 call %0 "%slnname%" "%platform%" Release "%target%" "%maxcpucount%" || set "failed=1"
 call %0 "%slnname%" "%platform%" Debug "%target%" "%maxcpucount%" || set "failed=1"
)
if "%config%" == "all" exit /b %failed%

rem MSBuild.exe options.
set platform_opt=/p:Platform="%platform%"
set config_opt=/p:Configuration="%config%"
set target_opt=/t:"%target%"
set cpu_opt=/maxcpucount
if not "%maxcpucount%" == "" set "cpu_opt=%cpu_opt%:%maxcpucount%"

call "%thisfolder%msbuild.bat" "%slnname%" %platform_opt% %config_opt% %target_opt% %cpu_opt% /nologo /verbosity:quiet /consoleloggerparameters:ErrorsOnly
exit /b %ERRORLEVEL% 

:fail
echo Usage: %0 solution [platform] [configuration] [target]
exit /b 1

