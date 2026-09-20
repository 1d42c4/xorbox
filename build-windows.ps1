$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Push-Location $PSScriptRoot
try {
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'Formatting check failed' }
    & cargo clippy --locked --all-targets --target x86_64-pc-windows-msvc -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Clippy failed' }
    & cargo test --locked --release --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    & cargo build --locked --release --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    $packageDir = Join-Path $PSScriptRoot 'dist\windows-x86_64'
    New-Item -ItemType Directory -Force -Path $packageDir | Out-Null
    Copy-Item -LiteralPath 'target\x86_64-pc-windows-msvc\release\xorbox.exe' -Destination $packageDir
    Copy-Item -LiteralPath 'README.md' -Destination $packageDir
    Write-Output "Built $packageDir\xorbox.exe"
} finally {
    Pop-Location
}
