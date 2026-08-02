[CmdletBinding()]
param(
    [string]$Python = "py",
    [string]$OutputRoot = "",
    [string]$BuildEnvironmentRoot = "",
    [string]$SourceCommit = "",
    [switch]$PreserveBuildEnvironment,
    [switch]$ReturnBuildState
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "windows_packaging_lib.ps1")

function Assert-NativeSuccess([string]$Message) {
    if ($LASTEXITCODE -ne 0) { throw $Message }
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputRoot) { $OutputRoot = Join-Path $root "dist-windows-private" }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$trustedOutputParent = Get-WindowsPackagingOutputParent `
    -SourceRoot $root -OutputRoot $OutputRoot
$outputRootOwnership = $null
$buildEnvironmentOwnership = $null
$stageOwnership = $null
$helperOwnership = $null
$sourceArchivePin = $null
$completed = $false
$helperResult = $null
$bodyError = $null
try {
    if ($null -ne (Get-Item -LiteralPath $OutputRoot -Force -ErrorAction SilentlyContinue)) {
        throw "The private Windows build output must be fresh."
    }
    $outputRootOwnership = New-ContainedOrdinaryDirectory `
        -TrustedRoot $trustedOutputParent -Candidate $OutputRoot

    $outputPrefix = $OutputRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $BuildEnvironmentRoot) {
        $BuildEnvironmentRoot = Join-Path $OutputRoot `
            (".helper-tools-" + [Guid]::NewGuid().ToString("N"))
    }
    $BuildEnvironmentRoot = [IO.Path]::GetFullPath($BuildEnvironmentRoot)
    if (-not $BuildEnvironmentRoot.StartsWith(
        $outputPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "The Windows helper build environment must remain beneath its private output root."
    }
    if ($null -ne (Get-Item `
        -LiteralPath $BuildEnvironmentRoot `
        -Force `
        -ErrorAction SilentlyContinue
    )) {
        throw "The Windows helper build environment must be fresh."
    }
    $buildEnvironmentOwnership = New-ContainedOrdinaryDirectory `
        -TrustedRoot $OutputRoot -Candidate $BuildEnvironmentRoot `
        -TrustedRootOwnership $outputRootOwnership

    $projectInstallSource = $root
    if ([Environment]::GetEnvironmentVariable(
        "TVTIME_IMMUTABLE_WINDOWS_RELEASE_SOURCE",
        "Process"
    ) -ceq "1") {
        if ($SourceCommit -notmatch '^[0-9a-f]{40}$') {
            throw "The reviewed Windows helper source commit was invalid."
        }
        $checkoutRoot = [IO.Path]::GetFullPath([Environment]::GetEnvironmentVariable(
            "TVTIME_WINDOWS_RELEASE_CHECKOUT_ROOT",
            "Process"
        ))
        $gitExecutable = (
            Get-Command git -CommandType Application -ErrorAction Stop |
                Select-Object -First 1
        ).Source
        $sourceArchive = Join-Path $BuildEnvironmentRoot "reviewed-source.tar.gz"
        & $gitExecutable -C $checkoutRoot archive `
            --format=tar.gz "--output=$sourceArchive" $SourceCommit
        Assert-NativeSuccess "The reviewed Windows helper source archive could not be created."
        $nativeBuildEnvironment = Get-OwnershipNativeCapability `
            -OwnershipToken $buildEnvironmentOwnership
        $identityPin = [TVTimeWindowsPackaging.FileCapabilities]::OpenBuildSourceIdentityPin(
            $nativeBuildEnvironment.Handle
        )
        try {
            $sourceArchiveIdentity = $identityPin.Identity
        } finally {
            $identityPin.Dispose()
        }
        $sourceArchivePin = [TVTimeWindowsPackaging.FileCapabilities]::OpenBuildSourceStrictReadPin(
            $nativeBuildEnvironment.Handle,
            $sourceArchiveIdentity
        )
        $projectInstallSource = $sourceArchive
    }

    $tools = $BuildEnvironmentRoot
    $venv = Join-Path $BuildEnvironmentRoot "venv"
    $pythonExe = Join-Path $venv "Scripts\python.exe"
    if ($Python -eq "py") {
        & py -3.13 -B -I -m venv $venv | Out-Host
    } else {
        & $Python -B -I -m venv $venv | Out-Host
    }
    Assert-NativeSuccess "The reviewed Windows helper environment could not be created."
$version = & $pythonExe -B -I -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
Assert-NativeSuccess "The reviewed Windows helper Python could not be inspected."
if ($version.Trim() -ne "3.13.12") { throw "Windows helper builds require reviewed Python 3.13.12." }
& $pythonExe -B -I -c "import platform, struct; raise SystemExit(0 if struct.calcsize('P') == 8 and platform.machine().casefold() in {'amd64', 'x86_64'} else 1)"
Assert-NativeSuccess "Windows helper builds require reviewed x64 Python."

& $pythonExe -B -I -m pip install --disable-pip-version-check --no-compile --require-hashes --only-binary=:all: -r (Join-Path $root "requirements-windows-build.lock") | Out-Host
Assert-NativeSuccess "The hash-locked Windows helper dependencies could not be installed."
& $pythonExe -B -I -m pip install --disable-pip-version-check --no-compile --no-index --no-build-isolation --no-deps $projectInstallSource | Out-Host
$sourceInstallExitCode = $LASTEXITCODE
if ($null -ne $sourceArchivePin) {
    $sourceArchivePin.Dispose()
    $sourceArchivePin = $null
}
if ($sourceInstallExitCode -ne 0) {
    throw "The local Windows helper source could not be installed."
}
& $pythonExe -B -I -m pip check | Out-Host
Assert-NativeSuccess "The Windows helper dependency environment is inconsistent."
& $pythonExe -B -I (Join-Path $root "script\verify_windows_python_environment.py") | Out-Host
Assert-NativeSuccess "The installed Windows helper dependency bytes did not match their RECORD hashes."

$stage = Join-Path $OutputRoot (".helper-stage-" + [Guid]::NewGuid().ToString("N"))
$dist = Join-Path $stage "dist"
$work = Join-Path $stage "work"
$spec = Join-Path $stage "spec"
$stageOwnership = New-ContainedOrdinaryDirectory `
    -TrustedRoot $OutputRoot -Candidate $stage `
    -TrustedRootOwnership $outputRootOwnership
foreach ($directory in @($dist, $work, $spec)) {
    $directoryOwnership = New-ContainedOrdinaryDirectory `
        -TrustedRoot $stage -Candidate $directory `
        -TrustedRootOwnership $stageOwnership
    Release-ContainedOrdinaryDirectoryOwnership -OwnershipToken $directoryOwnership
}
$fontRoot = & $pythonExe -B -I -c "from pathlib import Path; import reportlab; print((Path(reportlab.__file__).resolve().parent/'fonts').resolve(strict=True))"
Assert-NativeSuccess "The reviewed ReportLab font root could not be inspected."
$fonts = @("Vera.ttf", "VeraBd.ttf", "VeraIt.ttf", "VeraBI.ttf", "bitstream-vera-license.txt")
$dataArgs = @()
foreach ($font in $fonts) {
    $fontPath = Join-Path $fontRoot.Trim() $font
    if (-not (Test-Path $fontPath -PathType Leaf)) { throw "A reviewed ReportLab font resource is missing." }
    $dataArgs += @("--add-data", ($fontPath + ";reportlab/fonts"))
}

# In immutable release mode, $root is the recursively ACL-locked and
# inventory-verified Git stage. The pinned archive above is only pip's
# out-of-tree build input; PyInstaller deliberately consumes the locked stage.
& $pythonExe -B -I -m PyInstaller --clean --noconfirm --onedir --console --noupx `
    --name tvtime-helper --contents-directory _internal @dataArgs --paths $root `
    --distpath $dist --workpath $work --specpath $spec `
    (Join-Path $root "scripts\windows_helper_entry.py") | Out-Host
Assert-NativeSuccess "PyInstaller could not build the private Windows helper."
$helper = Join-Path $dist "tvtime-helper"
if (-not (Test-Path (Join-Path $helper "tvtime-helper.exe") -PathType Leaf)) {
    throw "PyInstaller did not create the private Windows helper."
}
& $pythonExe -B -I (Join-Path $root "script\scan_macos_release.py") --root $helper --forbidden-value $root | Out-Host
Assert-NativeSuccess "The private Windows helper failed its privacy scan."
$helperOwnership = New-ContainedOrdinaryTreeSnapshot `
    -TrustedRoot $dist -Candidate $helper
# The exact tree that will be promoted is scanned again while all of its
# directory and file capabilities deny mutation and replacement.
& $pythonExe -B -I (Join-Path $root "script\scan_macos_release.py") --root $helper --forbidden-value $root | Out-Host
Assert-NativeSuccess "The locked private Windows helper failed its privacy scan."

$final = Join-Path $OutputRoot "helper"
Assert-ContainedOrdinaryDirectoryOwnership `
    -OwnershipToken $outputRootOwnership | Out-Null
if (Test-Path $final) { throw "A previous private helper build exists. Remove it only after review." }
$helperOwnership = Move-ContainedOrdinaryDirectory `
    -OwnershipToken $helperOwnership `
    -DestinationTrustedRoot $OutputRoot `
    -Destination $final `
    -DestinationRootOwnership $outputRootOwnership
$completed = $true
$helperResult = if ($ReturnBuildState) {
    [pscustomobject]@{
        HelperRoot = $final
        OutputRootOwnership = $outputRootOwnership
        BuildEnvironmentOwnership = $buildEnvironmentOwnership
        HelperOwnership = $helperOwnership
        HelperManifest = $helperOwnership.Manifest
    }
} else {
    $final
}
} catch {
    $bodyError = $_
} finally {
    if ($null -ne $sourceArchivePin) {
        $sourceArchivePin.Dispose()
        $sourceArchivePin = $null
    }
    $cleanupTokens = @()
    if (-not $completed) { $cleanupTokens += $helperOwnership }
    $cleanupTokens += $stageOwnership
    if (-not $PreserveBuildEnvironment -or -not $completed) {
        $cleanupTokens += $buildEnvironmentOwnership
    }
    if (-not $completed) {
        $cleanupTokens += $outputRootOwnership
    }
    Remove-ContainedOrdinaryTrees `
        -OwnershipTokens $cleanupTokens `
        -PrimaryError $bodyError
}
if ($completed -and -not $ReturnBuildState) {
    Release-ContainedOrdinaryDirectoryOwnership -OwnershipToken $helperOwnership
    Release-ContainedOrdinaryDirectoryOwnership -OwnershipToken $outputRootOwnership
    if ($PreserveBuildEnvironment) {
        Release-ContainedOrdinaryDirectoryOwnership `
            -OwnershipToken $buildEnvironmentOwnership
    }
}
Write-Output $helperResult
