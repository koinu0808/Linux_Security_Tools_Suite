@echo off

echo 開始安裝LSTS所需套件...

echo.

set ERRORS=0

:: 安裝 Python
winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements
if errorlevel 1 (
    set /a ERRORS+=1
)

:: 更新 pip 套件管理器
py -3.12 -m pip install --upgrade pip
if errorlevel 1 (
    set /a ERRORS+=1
)

:: 安裝 PyQt5
py -3.12 -m pip install PyQt5
if errorlevel 1 (
    set /a ERRORS+=1
)

echo.

if %ERRORS%==0 (
    echo 安裝完畢，未發現安裝錯誤。
) else (
    echo 已安裝完畢，發現 %ERRORS% 個安裝錯誤。
)