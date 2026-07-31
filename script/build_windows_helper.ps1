[CmdletBinding()]
param(
    [string]$Python = "py",
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-NativeSuccess([string]$Message) {
    if ($LASTEXITCODE -ne 0) { throw $Message }
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputRoot) { $OutputRoot = Join-Path $root "dist-windows-private" }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (-not $OutputRoot.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The private Windows build output must remain beneath the repository build root."
}

$tools = Join-Path $root ".build-tools\windows-x64"
$venv = Join-Path $tools "venv"
$pythonExe = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $pythonExe -PathType Leaf)) {
    New-Item -ItemType Directory -Force $tools | Out-Null
    if ($Python -eq "py") {
        & py -3.13 -m venv $venv | Out-Host
    } else {
        & $Python -m venv $venv | Out-Host
    }
    Assert-NativeSuccess "The reviewed Windows helper environment could not be created."
}
$version = & $pythonExe -I -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
Assert-NativeSuccess "The reviewed Windows helper Python could not be inspected."
if ($version.Trim() -ne "3.13.12") { throw "Windows helper builds require reviewed Python 3.13.12." }

& $pythonExe -I -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r (Join-Path $root "requirements-windows-build.lock") | Out-Host
Assert-NativeSuccess "The hash-locked Windows helper dependencies could not be installed."
& $pythonExe -I -m pip install --disable-pip-version-check --no-index --no-build-isolation --no-deps $root | Out-Host
Assert-NativeSuccess "The local Windows helper source could not be installed."
& $pythonExe -I -m pip check | Out-Host
Assert-NativeSuccess "The Windows helper dependency environment is inconsistent."

$stage = Join-Path $OutputRoot (".helper-stage-" + [Guid]::NewGuid().ToString("N"))
$dist = Join-Path $stage "dist"
$work = Join-Path $stage "work"
$spec = Join-Path $stage "spec"
New-Item -ItemType Directory -Force $dist, $work, $spec | Out-Null
$fontRoot = & $pythonExe -I -c "from pathlib import Path; import reportlab; print((Path(reportlab.__file__).resolve().parent/'fonts').resolve(strict=True))"
Assert-NativeSuccess "The reviewed ReportLab font root could not be inspected."
$fonts = @("Vera.ttf", "VeraBd.ttf", "VeraIt.ttf", "VeraBI.ttf", "bitstream-vera-license.txt")
$dataArgs = @()
foreach ($font in $fonts) {
    $fontPath = Join-Path $fontRoot.Trim() $font
    if (-not (Test-Path $fontPath -PathType Leaf)) { throw "A reviewed ReportLab font resource is missing." }
    $dataArgs += @("--add-data", ($fontPath + ";reportlab/fonts"))
}

& $pythonExe -I -m PyInstaller --clean --noconfirm --onedir --console --noupx `
    --name tvtime-helper --contents-directory _internal @dataArgs --paths $root `
    --distpath $dist --workpath $work --specpath $spec `
    (Join-Path $root "scripts\windows_helper_entry.py") | Out-Host
Assert-NativeSuccess "PyInstaller could not build the private Windows helper."
$helper = Join-Path $dist "tvtime-helper"
if (-not (Test-Path (Join-Path $helper "tvtime-helper.exe") -PathType Leaf)) {
    throw "PyInstaller did not create the private Windows helper."
}
& $pythonExe -I (Join-Path $root "script\scan_macos_release.py") --root $helper --forbidden-value $root | Out-Host
Assert-NativeSuccess "The private Windows helper failed its privacy scan."

$final = Join-Path $OutputRoot "helper"
New-Item -ItemType Directory -Force $OutputRoot | Out-Null
if (Test-Path $final) { throw "A previous private helper build exists. Remove it only after review." }
Move-Item -LiteralPath $helper -Destination $final
Remove-Item -LiteralPath $stage -Recurse -Force
Write-Output $final
