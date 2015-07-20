@echo off
setlocal

rem Launches msbuild.exe with supplied parameters.
rem TBD: Use 64-bit version of MSBuild.exe if available?
rem Use VS2013 MSBuild if available, else fall back to VS2010.
rem Note it won't hurt to always use newer msbuild when available, because
rem projects still build with the VS runtimes that the project file says to.
if not exist "%MSBUILD_EXE%" (
 set "MSBUILD_EXE=%ProgramFiles(x86)%\MSBuild\12.0\Bin\MSBuild.exe"
)
if not exist "%MSBUILD_EXE%" (
 set "MSBUILD_EXE=%WinDir%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
)

echo START: MSBuild.exe %* %MSBUILD_OPTS%
"%MSBUILD_EXE%" %* %MSBUILD_OPTS%
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL% 

echo MSBuild.exe succeeded.
exit /b 0

