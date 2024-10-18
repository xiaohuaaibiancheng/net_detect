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
echo [INFO] 运行Python脚本: app.py
start /b python app.py

REM 显示进度条
echo [INFO] 等待服务器启动...

setlocal enabledelayedexpansion
set "progress="
for /L %%i in (1,1,15) do (
    set "progress=!progress!#"
    <nul set /p =等待中: !progress!
    timeout /t 1 /nobreak >nul
    cls
)

REM 结束进度条
echo 服务器启动成功!

REM 打开本地网页
echo [INFO] 打开浏览器: http://localhost:5000/login
start "" "http://localhost:5000/login"

REM 显示完成消息
echo.
echo ***********************************
echo *     服务器启动成功，网页已打开    *
echo ***********************************
echo.

REM 暂停以保持命令提示符窗口打开
pause
