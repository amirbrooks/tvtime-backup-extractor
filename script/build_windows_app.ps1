[CmdletBinding()]
param([string]$OutputRoot = "")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputRoot) { $OutputRoot = Join-Path $root "dist-windows-private" }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$helperRoot = & (Join-Path $PSScriptRoot "build_windows_helper.ps1") -OutputRoot $OutputRoot
$project = Join-Path $root "windows\TVTimeRecovery.Windows\TVTimeRecovery.Windows.csproj"
$helperDestination = Join-Path (Split-Path $project) "Helpers"
$assetDestination = Join-Path (Split-Path $project) "Assets"
$noticeDestination = Join-Path (Split-Path $project) "Notices"
if (Test-Path $helperDestination) { throw "The generated helper staging directory already exists." }
if (Test-Path $assetDestination) { throw "The generated Windows asset staging directory already exists." }
if (Test-Path $noticeDestination) { throw "The generated Windows notice staging directory already exists." }
New-Item -ItemType Directory $helperDestination | Out-Null
try {
    Copy-Item -Path (Join-Path $helperRoot "*") -Destination $helperDestination -Recurse
    New-Item -ItemType Directory $assetDestination | Out-Null
    Add-Type -AssemblyName System.Drawing
    $sourceIcon = [Drawing.Image]::FromFile((Join-Path $root "macos\Bundle\AppIcon-1024.png"))
    try {
        $assets = @(
            [pscustomobject]@{ Name = "StoreLogo.png"; Width = 50; Height = 50 }
            [pscustomobject]@{ Name = "Square44x44Logo.png"; Width = 44; Height = 44 }
            [pscustomobject]@{ Name = "Square150x150Logo.png"; Width = 150; Height = 150 }
            [pscustomobject]@{ Name = "Wide310x150Logo.png"; Width = 310; Height = 150 }
        )
        foreach ($asset in $assets) {
            $bitmap = [Drawing.Bitmap]::new([int]$asset.Width, [int]$asset.Height)
            $graphics = [Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.Clear([Drawing.Color]::Transparent)
                $scale = [Math]::Min(([double]$asset.Width / $sourceIcon.Width), ([double]$asset.Height / $sourceIcon.Height))
                $width = [int][Math]::Round($sourceIcon.Width * $scale)
                $height = [int][Math]::Round($sourceIcon.Height * $scale)
                $left = ([int]$asset.Width - $width) / 2
                $top = ([int]$asset.Height - $height) / 2
                $graphics.DrawImage($sourceIcon, [int]$left, [int]$top, $width, $height)
                $bitmap.Save((Join-Path $assetDestination $asset.Name), [Drawing.Imaging.ImageFormat]::Png)
            } finally {
                $graphics.Dispose()
                $bitmap.Dispose()
            }
        }
    } finally {
        $sourceIcon.Dispose()
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere -PathType Leaf)) { throw "A current Visual Studio installation with MSBuild and MSIX tooling is required." }
    $msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
    if (-not $msbuild) { throw "MSBuild was not found." }
    & $msbuild $project /t:Restore /p:RuntimeIdentifier=win-x64 /p:RestoreLockedMode=true | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "The locked Windows dependency restore failed." }
    $nugetRoot = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { Join-Path $env:USERPROFILE ".nuget\packages" }
    & (Join-Path $root ".build-tools\windows-x64\venv\Scripts\python.exe") -I `
        (Join-Path $root "script\collect_windows_licenses.py") `
        --output $noticeDestination `
        --nuget-lock (Join-Path (Split-Path $project) "packages.lock.json") `
        --nuget-root $nugetRoot `
        --project-license (Join-Path $root "LICENSE") `
        --notice (Join-Path $root "windows\THIRD_PARTY_NOTICES.md") | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "The private Windows license collection failed." }
    $msixOutputDirectory = (Join-Path $OutputRoot "msix") + [IO.Path]::DirectorySeparatorChar
    $appxPackageDirectoryArgument = "/p:AppxPackageDir=$msixOutputDirectory"
    & $msbuild $project /m /p:Configuration=Release /p:Platform=x64 `
        /p:RuntimeIdentifier=win-x64 /p:GenerateAppxPackageOnBuild=true `
        /p:AppxPackageSigningEnabled=false /p:AppxBundle=Never `
        $appxPackageDirectoryArgument | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "The private Windows MSIX build failed." }
} finally {
    if (Test-Path $helperDestination) { Remove-Item -LiteralPath $helperDestination -Recurse -Force }
    if (Test-Path $assetDestination) { Remove-Item -LiteralPath $assetDestination -Recurse -Force }
    if (Test-Path $noticeDestination) { Remove-Item -LiteralPath $noticeDestination -Recurse -Force }
}
$packages = @(Get-ChildItem (Join-Path $OutputRoot "msix") -Filter *.msix -File -Recurse)
if ($packages.Count -ne 1) { throw "Expected exactly one x64 private MSIX package." }
$scanRoot = Join-Path $OutputRoot (".msix-scan-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $scanRoot | Out-Null
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($packages[0].FullName, $scanRoot)
    & (Join-Path $root ".build-tools\windows-x64\venv\Scripts\python.exe") -I `
        (Join-Path $root "script\scan_macos_release.py") --root $scanRoot --forbidden-value $root | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "The private Windows MSIX failed its privacy scan." }
} finally {
    if (Test-Path $scanRoot) { Remove-Item -LiteralPath $scanRoot -Recurse -Force }
}
Write-Output $packages[0].FullName
