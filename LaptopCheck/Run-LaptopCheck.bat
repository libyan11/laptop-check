@echo off
title Laptop Check
cd /d "%~dp0"
echo.
echo  Starting Laptop Check...  (click YES on the administrator prompt)
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0LaptopCheck.ps1" %*
if errorlevel 1 (
  echo.
  echo  ---------------------------------------------------------------
  echo  The check could not start.
  echo  If the message above says "running scripts is disabled" or
  echo  "not digitally signed" and mentions Group Policy, that itself
  echo  means this PC is CONTROLLED BY A COMPANY POLICY - treat it as
  echo  company-locked.
  echo  ---------------------------------------------------------------
  pause
)
