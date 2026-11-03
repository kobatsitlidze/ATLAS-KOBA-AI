@echo off
cd /d "%~dp0"
py -3 atlas.py
if errorlevel 1 pause
