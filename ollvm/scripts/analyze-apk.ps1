param([string]$Apk = '', [string]$Out = 'analysis\out')
$ErrorActionPreference = 'Stop'; $root = Split-Path -Parent $PSScriptRoot
if (-not $Apk) { $Apk = Join-Path $root 'app\build\outputs\apk\debug\app-debug.apk' }
if (-not (Test-Path $Apk)) { throw "APK not found: $Apk. Build with scripts\build.ps1 first." }
$outPath = Join-Path $root $Out; New-Item -ItemType Directory -Force $outPath | Out-Null
$apktool = 'D:\tools\Security\Reverse\Android\static\apktool\apktool.bat'
if (Test-Path $apktool) { & $apktool d -f $Apk -o (Join-Path $outPath 'apktool') }
$jadx = Get-Command jadx -ErrorAction SilentlyContinue
if ($jadx) { & $jadx.Source -d (Join-Path $outPath 'jadx') $Apk } else { Write-Warning 'jadx is not on PATH; install it or set JADX_HOME.' }
$aapt2 = Join-Path $env:ANDROID_HOME 'build-tools\35.0.0\aapt2.exe'
if (Test-Path $aapt2) { & $aapt2 dump badging $Apk | Out-File (Join-Path $outPath 'aapt2-badging.txt') }
Write-Host "Analysis output: $outPath"
