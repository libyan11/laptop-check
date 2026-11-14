@echo off
title My Laptop Health Check
cd /d "%~dp0"
echo.
echo  My Laptop Health Check - for a laptop you have ALREADY bought.
echo  Deeper tests: full malware scan, longer CPU test, battery run-time,
echo  Windows Update check, after-purchase to-do list, history tracking.
echo  (click YES on the administrator prompt)
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0LaptopCheck.ps1" -Mode Own %*
if errorlevel 1 (
  echo.
  echo  ---------------------------------------------------------------
  echo  The check could not start.
  echo  If the message above says "running scripts is disabled" or
  echo  "not digitally signed" and mentions Group Policy, this laptop is
  echo  still CONTROLLED BY A COMPANY POLICY - contact the seller.
  echo  ---------------------------------------------------------------
  pause
)
