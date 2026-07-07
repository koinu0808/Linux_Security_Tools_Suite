@echo off

echo ========================
echo 安裝 Windows 套件...
echo ========================

call LSTS_installer.bat

echo.
echo ========================
echo 安裝 WSL 套件...
echo ========================

wsl bash ./LSTS_installer.sh

echo.
echo 全部完成
pause
