param([ValidateSet('debug','release')][string]$Variant = 'debug', [switch]$Install)
$ErrorActionPreference = 'Stop'; $root = Split-Path -Parent $PSScriptRoot
& (Join-Path $root 'build\bootstrap.ps1')
Push-Location $root
try {
  & .\gradlew.bat "assemble$($Variant.Substring(0,1).ToUpper()+$Variant.Substring(1))"
  $apk = Join-Path $root "app\build\outputs\apk\$Variant\app-$Variant.apk"
  if (Test-Path $apk) { Write-Host "APK=$apk" }
  if ($Install) { & adb install -r $apk; & adb shell am start -n com.example.ollvmlab/.MainActivity }
} finally { Pop-Location }
