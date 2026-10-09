@echo off
setlocal
cd /d "%~dp0"
echo ===========================================
echo   System Analysis Tool 1.3.1 - Windows Build
echo ===========================================
echo Project folder: %CD%
if not exist "%~dp0requirements.txt" (
  echo ERROR: requirements.txt was not found beside this script. Extract the ZIP fully first.
  pause
  exit /b 1
)
if not exist "%~dp0main.py" (
  echo ERROR: main.py was not found beside this script.
  pause
  exit /b 1
)
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher not found. Install Python 3.12 on the developer PC.
  pause
  exit /b 1
)
if not exist "%~dp0.venv\Scripts\python.exe" (
  py -3.12 -m venv "%~dp0.venv"
  if errorlevel 1 goto :fail
)
"%~dp0.venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :fail
"%~dp0.venv\Scripts\python.exe" -m pip install -r "%~dp0requirements.txt" pyinstaller
if errorlevel 1 goto :fail
"%~dp0.venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --windowed --onedir --name SystemAnalysisTool --collect-all psutil "%~dp0main.py"
if errorlevel 1 goto :fail
echo.
echo Build complete: dist\SystemAnalysisTool\SystemAnalysisTool.exe
pause
exit /b 0
:fail
echo Build failed. Review the error above.
pause
exit /b 1
