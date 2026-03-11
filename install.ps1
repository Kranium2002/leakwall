$ErrorActionPreference = "Stop"
$Repo = "Kranium2002/leakwall"

if (-not $env:VERSION) {
    $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $release.tag_name -replace '^v', ''
} else {
    $Version = $env:VERSION
}

$Target = "x86_64-pc-windows-msvc"
$Url = "https://github.com/$Repo/releases/download/v$Version/leakwall-$Version-$Target.zip"

Write-Host "Downloading leakwall v$Version for Windows..."

$TmpDir = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory $_ }
$ZipPath = Join-Path $TmpDir "leakwall.zip"

Invoke-WebRequest -Uri $Url -OutFile $ZipPath
Expand-Archive -Path $ZipPath -DestinationPath $TmpDir

$InstallDir = Join-Path $env:USERPROFILE ".cargo\bin"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Move-Item (Join-Path $TmpDir "leakwall.exe") (Join-Path $InstallDir "leakwall.exe") -Force
Remove-Item -Recurse $TmpDir

Write-Host "Installed leakwall to $InstallDir\leakwall.exe"
Write-Host "Make sure $InstallDir is in your PATH"
