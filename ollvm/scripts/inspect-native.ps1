param([string]$So = '')
$ErrorActionPreference = 'Stop'; $root = Split-Path -Parent $PSScriptRoot
if (-not $So) {
  $candidates = @(
    (Join-Path $root 'app\build\intermediates\cxx\Debug\*\obj\arm64-v8a\libollvmlab.so'),
    (Join-Path $root 'app\build\intermediates\stripped_native_libs\debug\stripDebugDebugSymbols\out\lib\arm64-v8a\libollvmlab.so')
  )
  foreach ($candidate in $candidates) {
    $found = Get-ChildItem -Path $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $So = $found.FullName; break }
  }
}
if (-not (Test-Path $So)) { throw "Native library not found: $So" }
$llvm = 'D:\tools\Security\Reverse\Android\dev\android-ndk-r27d\toolchains\llvm\prebuilt\windows-x86_64\bin'
$readelf = Join-Path $llvm 'llvm-readelf.exe'; $objdump = Join-Path $llvm 'llvm-objdump.exe'; $strings = Join-Path $llvm 'llvm-strings.exe'
Write-Host "== FILE =="; $file = Get-Item -LiteralPath $So; Write-Host ("{0} ({1} bytes)" -f $file.FullName,$file.Length)
Write-Host "== SYMBOLS =="; $symbols = (& $readelf -Ws $So 2>&1 | Out-String); $symbols -split "`r?`n" | Select-String 'Java_|decode_secret|nativeOpaque'
Write-Host "== SECTIONS =="; $sections = (& $readelf -S $So 2>&1 | Out-String); $sections -split "`r?`n" | Select-String '\.text|\.rodata|\.debug'
Write-Host "== STRINGS =="; if (Test-Path $strings) { $str = (& $strings $So 2>&1 | Out-String); $str -split "`r?`n" | Select-String 'ollvm|secret|JNI' } else { & $objdump -s -j .rodata $So }
Write-Host "== DISASSEMBLY =="; $dis = (& $objdump -d --demangle $So 2>&1 | Out-String); $dis -split "`r?`n" | Select-String -Context 2,12 'nativeSecret|nativeOpaque|decode_secret'
