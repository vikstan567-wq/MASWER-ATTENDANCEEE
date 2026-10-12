@echo off
title Maswer Attend
cd /d "%~dp0"
if not exist node_modules (
  echo Pehli baar: packages install ho rahe hain...
  call npm install
)
echo.
echo  Server start ho raha hai... browser khud khul jayega.
start "" http://localhost:3000
node server.js
pause
