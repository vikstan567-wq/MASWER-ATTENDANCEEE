@echo off
title Maswer Attend - Build Setup
echo.
echo  +========================================+
echo  ^|    +maswer attend - EXE Build Setup    ^|
echo  +========================================+
echo.
echo  Step 1: Packages install ho rahe hain...
echo.
call npm install
echo.
echo  Step 2: EXE build ho rahi hai (2-3 min lagenge)...
echo  (Internet se Node.js download hoga - wait karo)
echo.
call npx pkg app.js --target node18-win-x64 --output MaswerAttend.exe --compress GZip
echo.
if exist MaswerAttend.exe (
    echo  =========================================
    echo  SUCCESS! MaswerAttend.exe ban gayi!
    echo  =========================================
    echo.
    echo  Ab sirf "MaswerAttend.exe" double-click
    echo  karo - koi CMD nahi chahiye!
    echo.
    echo  public folder bhi saath rakhna zaroor!
) else (
    echo  Build fail ho gayi. Internet check karo.
)
echo.
pause
