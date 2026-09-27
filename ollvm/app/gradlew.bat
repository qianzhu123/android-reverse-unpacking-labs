@echo off
setlocal EnableExtensions
set "JAVA_HOME=D:\tools\Dev\Runtime\jdk21"
set "PATH=%JAVA_HOME%\bin;%PATH%"
set "ROOT=%~dp0"
set "LOCAL_GRADLE=%ROOT%tools\gradle-8.13\bin\gradle.bat"
if exist "%LOCAL_GRADLE%" goto run
for /f "usebackq delims=" %%G in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=Join-Path $env:USERPROFILE '.gradle\wrapper\dists\gradle-8.13-all'; if(Test-Path $p){$x=Get-ChildItem $p -Recurse -Filter gradle.bat | Select-Object -First 1 -ExpandProperty FullName; if($x){$x}}"`) do set "LOCAL_GRADLE=%%G"
if exist "%LOCAL_GRADLE%" goto run
echo Gradle 8.13 was not found. Run scripts\bootstrap.ps1 to download it.
exit /b 1
:run
call "%LOCAL_GRADLE%" %*
set "EXIT_CODE=%ERRORLEVEL%"
endlocal & exit /b %EXIT_CODE%
