@echo off

::for test signing create TestADDriversStore

pushd %~dp0

makecert -sr currentUser -ss TestADDriversStore -n CN=TestAD
certmgr -del -all -c -s TestADDriversStore
