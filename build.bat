@echo off
set GOOS=windows
set GOARCH=amd64
go build -trimpath -ldflags "-H=windowsgui -s -w" -o NetSwitch.exe .
if %errorlevel%==0 echo Готово: NetSwitch.exe
pause
