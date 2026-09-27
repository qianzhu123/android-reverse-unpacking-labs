param([ValidateSet('debug','release')][string]$Variant = 'debug', [switch]$Install)
$ErrorActionPreference = 'Stop'; $root = Split-Path -Parent $PSScriptRoot
& (Join-Path $root 'build\bootstrap.ps1')
# gradle 工程根在 app\（单模块：settings.gradle + build.gradle 都在 app\ 内）
$gradleRoot = Join-Path $root 'app'
Push-Location $gradleRoot
try {
  & .\gradlew.bat "assemble$($Variant.Substring(0,1).ToUpper()+$Variant.Substring(1))"
  $apk = Join-Path $gradleRoot "build\outputs\apk\$Variant\app-$Variant.apk"
  if (Test-Path $apk) { Write-Host "APK=$apk" }
  if ($Install) { & adb install -r $apk; & adb shell am start -n com.example.ollvmlab/.MainActivity }
} finally { Pop-Location }
