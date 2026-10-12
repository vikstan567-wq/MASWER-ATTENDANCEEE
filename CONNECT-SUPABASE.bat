@echo off
title Maswer Attend - Supabase Connect
cd /d "%~dp0"
if not exist node_modules (
  echo Packages install ho rahe hain...
  call npm install
)
echo.
echo  Supabase ka DATABASE_URL paste karo (poora link, password ke saath)
echo  Jaise: postgresql://postgres.xxxx:PASSWORD@aws-0-ap-south-1.pooler.supabase.com:6543/postgres
echo.
set /p DATABASE_URL=DATABASE_URL: 
echo.
node check-db.js
if errorlevel 1 (
  pause
  exit /b 1
)
echo  Ab server start ho raha hai (is window ko band mat karna)...
start "" http://localhost:3000
node server.js
pause
