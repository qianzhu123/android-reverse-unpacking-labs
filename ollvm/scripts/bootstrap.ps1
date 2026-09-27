param([switch]$SkipGradle)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$javaHome = 'D:\tools\Dev\Runtime\jdk21'
if (-not (Test-Path "$javaHome\bin\java.exe")) { throw "JDK 21 not found at $javaHome" }
$env:JAVA_HOME = $javaHome
$env:Path = "$javaHome\bin;" + $env:Path
$gradleHome = Join-Path $root 'tools\gradle-8.13'
if (-not $SkipGradle -and -not (Test-Path (Join-Path $gradleHome 'bin\gradle.bat'))) {
  $zip = Join-Path $root 'tools\gradle-8.13-bin.zip'
  New-Item -ItemType Directory -Force (Split-Path $zip) | Out-Null
  Invoke-WebRequest 'https://services.gradle.org/distributions/gradle-8.13-bin.zip' -OutFile $zip
  Expand-Archive -Path $zip -DestinationPath (Join-Path $root 'tools') -Force
  Remove-Item -LiteralPath $zip -Force
}
Write-Host "JAVA_HOME=$env:JAVA_HOME"
Write-Host "SDK=$env:ANDROID_HOME"
Write-Host "NDK=D:\tools\Security\Reverse\Android\dev\android-ndk-r27d"
if (Test-Path (Join-Path $gradleHome 'bin\gradle.bat')) { Write-Host "Gradle ready: $gradleHome" } else { Write-Host 'Gradle not downloaded; gradlew.bat will use the user cache if available.' }
