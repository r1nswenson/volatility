@rem Do not run this directly.  It is executed by the maven build process.
@echo off
setlocal
cd /d "%~dp0.."
call target\dependency\tools\prep.bat
@echo off
call "%~dp0versions.bat"
set workdir=%cd%
if not exist %SYSTEMDRIVE%\%PYTHONDIR% (
 cd ..\..\src
 wget --no-check-certificate -N https://www.python.org/ftp/python/%PYTHONVER%/python-%PYTHONVER%.amd64.msi
 if errorlevel 1 goto error
 echo installing python
 msiexec /i python-%PYTHONVER%.amd64.msi /qn
 echo install done.
)

if not exist "C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" (
	echo Visual Studio C++ 9.0 must be installed
)

@rem check for deps
if not exist %SYSTEMDRIVE%\%PYTHONDIR%\Scripts\pyinstaller.exe (
	pushd %SYSTEMDRIVE%\%PYTHONDIR%\
	copy "%~dp0\ez_setup.py" .
	if errorlevel 1 goto error
	
	python ez_setup.py install
	if errorlevel 1 goto error

	popd

	pushd %SYSTEMDRIVE%\%PYTHONDIR%\Scripts\
	
	call "C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" amd64

	easy_install argparse
	if errorlevel 1 goto error

	easy_install PyYAML
	if errorlevel 1 goto error

	easy_install pytz
	if errorlevel 1 goto error

	easy_install protobuf
	if errorlevel 1 goto error

	easy_install pycrypto
	if errorlevel 1 goto error

	easy_install pyelftools
	if errorlevel 1 goto error

	easy_install acora
	if errorlevel 1 goto error

	easy_install codegen
	if errorlevel 1 goto error

	easy_install pefile
	if errorlevel 1 goto error

	easy_install hexdump
	if errorlevel 1 goto error

	easy_install Flask
	if errorlevel 1 goto error

	easy_install pyinstaller
	if errorlevel 1 goto error
	
	::This is a complete hack as distorm 3.3.0 completely fails with pyinstall 	
	echo xcopy /D /Y /K /I /E "%~dp0\distorm3\distorm3-3-py2.7.egg-x64" ..\lib\site-packages\distorm3-3.py2.7.egg
	xcopy /D /Y /K /I /E "%~dp0\distorm3\distorm3-3-py2.7.egg-x64" ..\lib\site-packages\distorm3-3.py2.7.egg
	if errorlevel 1 goto error
	
	easy_install distorm3
	if errorlevel 1 goto error
	
	popd
)

@rem check for pywin32
if not exist %SYSTEMDRIVE%\%PYTHONDIR%\Scripts\pywin32_postinstall.py (
 echo You need to install pywin32.amd64.  Look in the build dir for a pywin
 goto error
)

if not exist %SYSTEMDRIVE%\%PYTHONDIR%\lib\site-packages\yara.pyd (
 echo You need to install yara-python.amd64.  Look in the buildutils dir
 goto error
)


if not exist %SYSTEMDRIVE%\%PYTHONDIR%.32 (
 cd ..\..\src
 wget --no-check-certificate -N https://www.python.org/ftp/python/%PYTHONVER32%/python-%PYTHONVER32%.msi
 if errorlevel 1 goto error
 echo installing python
 msiexec /i python-%PYTHONVER32%.msi /qn TARGETDIR=%SYSTEMDRIVE%\%PYTHONDIR%.32
 echo install done.
)

@rem check for deps
if not exist %SYSTEMDRIVE%\%PYTHONDIR%.32\Scripts\pyinstaller.exe (
	pushd %SYSTEMDRIVE%\%PYTHONDIR%.32\
	copy "%~dp0\ez_setup.py" .
	if errorlevel 1 goto error
	
	python ez_setup.py install
	if errorlevel 1 goto error

	popd

	pushd %SYSTEMDRIVE%\%PYTHONDIR%.32\Scripts\
	
	call "C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" amd64

	easy_install argparse
	if errorlevel 1 goto error

	easy_install PyYAML
	if errorlevel 1 goto error

	easy_install pytz
	if errorlevel 1 goto error

	easy_install protobuf
	if errorlevel 1 goto error

	easy_install pycrypto
	if errorlevel 1 goto error

	easy_install pyelftools
	if errorlevel 1 goto error

	easy_install acora
	if errorlevel 1 goto error

	easy_install codegen
	if errorlevel 1 goto error

	easy_install pefile
	if errorlevel 1 goto error

	easy_install hexdump
	if errorlevel 1 goto error

	easy_install Flask
	if errorlevel 1 goto error

	easy_install pyinstaller
	if errorlevel 1 goto error
	
	::This is a complete hack as distorm 3.3.0 completely fails with pyinstall 	
	echo xcopy /D /Y /K /I /E "%~dp0\distorm3\distorm3-3-py2.7.egg-win32" ..\lib\site-packages\distorm3-3.py2.7.egg
	xcopy /D /Y /K /I /E "%~dp0\distorm3\distorm3-3-py2.7.egg-win32" ..\lib\site-packages\distorm3-3.py2.7.egg
	if errorlevel 1 goto error
	
	easy_install distorm3
	if errorlevel 1 goto error
	
	popd
)

@rem check for pywin32.32
if not exist %SYSTEMDRIVE%\%PYTHONDIR%.32\Scripts\pywin32_postinstall.py (
 echo You need to install pywin32.  Look in the buildutils dir
 goto error
)

if not exist %SYSTEMDRIVE%\%PYTHONDIR%.32\lib\site-packages\yara.pyd (
 echo You need to install yara-python.win32.  Look in the buildutils dir
 goto error
)


exit /b 0
:error
echo Failed.
exit /b 1
