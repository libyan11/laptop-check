@echo off
title Laptop Check - Selling
cd /d "%~dp0"
echo.
echo  Laptop Check - SELLING mode.
echo  Tests your laptop, then writes a ready-to-paste eBay listing
echo  (specs + test results + known issues) and a before-selling
echo  privacy checklist. Run it BEFORE you wipe the laptop.
echo  (click YES on the administrator prompt)
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0LaptopCheck.ps1" -Mode Sell %*
if errorlevel 1 (
  echo.
  echo  The check could not start - see the message above.
  pause
)
