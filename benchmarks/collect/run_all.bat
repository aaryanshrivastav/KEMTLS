@echo off
setlocal DisableDelayedExpansion

cd /d "%~dp0\..\.."
python benchmarks\run_benchmarks.py
endlocal
