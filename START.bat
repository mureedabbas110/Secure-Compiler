@echo off
title Secure Compiler
cd /d "%~dp0"
where python >nul 2>nul && (python run.py) || (py run.py)
echo.
echo If you see an error above, send it to me.
pause
