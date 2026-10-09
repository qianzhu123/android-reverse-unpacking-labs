# fetch_external.ps1 — 可选：拉取开源的 Android VMP 靶场/参考实现到 tools/（**不进 git**）
#
# 说明：
#   · 本 lab 的主线是**自建样本**（L1..L5 / S1..S3，见 build/ 与 tools/）。
#   · 本脚本只负责把你**想额外练习**的开源 Android 侧靶场/保护器源码 clone 到
#     tools/external/，它们被 .gitignore 排除，不会进仓库。
#   · 商业保护器（VMProtect / Themida）的受保护样本**无法自建也无法分发** —— 本脚本
#     只拉「开源、可自行编译出靶场」的项目，以及 PE 侧概念参考仓库。
#
# 用法（PowerShell，在 lab 根目录执行）：
#   .\build\fetch_external.ps1            # 列出可选项并询问
#   .\build\fetch_external.ps1 -All       # 全部拉取
#   .\build\fetch_external.ps1 -Only amice,xVMP
#
# 需要本机有 git 且能访问 github.com。

param(
    [switch]$All,
    [string[]]$Only = @()
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Dest = Join-Path $Root 'tools/external'
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

# name -> repo url ；kind: android=可编译出 Arm 靶场/保护器；pe=PE 侧概念参考
$REPOS = [ordered]@{
    'amice'         = 'https://github.com/fuqiuluo/amice'                 # Rust/LLVM VMP for Android（开源保护器）
    'xVMP'          = 'https://github.com/Kotoamatsukami233/xVMP'         # Android ELF VM protection
    'XopProtector'  = 'https://github.com/xopJack/XopProtector'           # Android protector (含 VMP)
    'AndroidSoRecon'= 'https://github.com/La0D3ng0/AndroidSoRecon'        # Android SO VMP recon
    'NoVmp'         = 'https://github.com/can1357/NoVmp'                  # PE: VMProtect x64 静态去虚拟化
    'awesome-vmp'   = 'https://github.com/lmy375/awesome-vmp'              # PE: VMP 分析资料总表
}

function Show-List {
    Write-Host "可拉取的开源靶场/参考（clone 到 tools/external/<name>，不进 git）："
    foreach ($k in $REPOS.Keys) { Write-Host ("  {0,-16} {1}" -f $k, $REPOS[$k]) }
}

$targets = @()
if ($All) { $targets = $REPOS.Keys }
elseif ($Only.Count -gt 0) { $targets = $Only }
else { Show-List; Write-Host "`n用 -All 或 -Only <逗号分隔的名字> 指定要拉取的项目。"; exit 0 }

foreach ($name in $targets) {
    if (-not $REPOS.Contains($name)) { Write-Warning "未知项目：$name（跳过）"; continue }
    $url = $REPOS[$name]
    $out = Join-Path $Dest $name
    if (Test-Path $out) { Write-Host "[skip] $name 已存在：$out"; continue }
    Write-Host "[clone] $name <- $url"
    try {
        git clone --depth 1 $url $out
    } catch {
        Write-Warning "[fail] $name 拉取失败：$_"
    }
}
Write-Host "`n完成。外部项目在 $Dest（已在 .gitignore 中排除）。"
