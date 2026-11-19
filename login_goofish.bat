@echo off
setlocal
cd /d "%~dp0"
set "PY=C:\softwarepro\anaconda\envs\goofish\python.exe"
if not exist "%PY%" set "PY=python"
echo Starting local Goofish login helper...
echo Do not type passwords or codes in this window.
"%PY%" -m src.login_helper %*
set "ERR=%ERRORLEVEL%"
echo.
echo Login helper finished with exit code %ERR%.
echo This window can be closed after you have read the message above.
pause
exit /b %ERR%
