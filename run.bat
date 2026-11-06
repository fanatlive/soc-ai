@echo off
rem Запуск одной командой (Windows):  run.bat            - локально
rem                                   run.bat --remote   - доступ с других компьютеров
chcp 65001 >nul
cd /d "%~dp0"
if "%PORT%"=="" set PORT=8000
if not exist .venv\Scripts\python.exe py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -q -r requirements.txt
.venv\Scripts\python.exe -m tools.setup_env %*
.venv\Scripts\python.exe -m tools.check_llm
set HOST=127.0.0.1
if "%1"=="--remote" set HOST=0.0.0.0
echo Запуск: http://127.0.0.1:%PORT%  (Ctrl+C - остановить)
.venv\Scripts\python.exe -m uvicorn backend.main:app --host %HOST% --port %PORT%
