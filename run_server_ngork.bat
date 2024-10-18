@echo off
REM 设置UTF-8编码
chcp 65001 >nul
REM 设置颜色
color 0A

REM 显示开始消息
echo ***********************************
echo *        启动服务器脚本          *
echo ***********************************
echo.

REM 初始化Conda环境，在这里修改虚拟环境
echo [INFO] 激活Conda环境: detect
REM 修改这一行的虚拟环境即可，如你的虚拟环境是myenv，则改为conda.bat activate myenv
CALL conda.bat activate detect

REM 检查Conda环境是否激活成功
IF ERRORLEVEL 1 (
    echo [ERROR] Conda环境激活失败
    pause
    exit /b 1
)

REM 运行Python脚本
echo [INFO] 运行Python脚本: sever.py
start /b python sever.py

REM 等待几秒钟以确保服务器启动
echo [INFO] 等待服务器启动...
timeout /t 15 /nobreak >nul

setlocal enabledelayedexpansion
set "progress="
for /L %%i in (1,1,15) do (
    set "progress=!progress!#"
    <nul set /p =等待中: !progress!
    timeout /t 1 /nobreak >nul
    cls
)
REM 检查Python脚本是否运行成功
IF ERRORLEVEL 1 (
    echo [ERROR] Python脚本运行失败
    pause
    exit /b 1
)

REM 从文件中读取Ngrok URL
setlocal enabledelayedexpansion
set "ngrok_url="
for /f "usebackq delims=" %%x in ("ngrok_url.txt") do (
    set "ngrok_url=%%x"
)
endlocal & set "ngrok_url=%ngrok_url%"

REM 检查是否成功读取URL
IF "%ngrok_url%"=="" (
    echo [ERROR] 无法读取Ngrok URL
    pause
    exit /b 1
)

REM 打开网页
echo [INFO] 打开浏览器: %ngrok_url%
start "" "%ngrok_url%"

REM 显示完成消息
echo.
echo ***********************************
echo *     服务器启动成功，网页已打开    *
echo ***********************************
echo.

REM 暂停以保持命令提示符窗口打开
pause
