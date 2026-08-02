[CmdletBinding()]
param(
    [string]$OutputRoot = "",
    [string]$Python = "py",
    [string]$SourceCommit = "",
    [string]$SourceTree = "",
    [switch]$ReturnBuildState
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "windows_packaging_lib.ps1")
. (Join-Path $PSScriptRoot "windows_msix_integrity.ps1")
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputRoot) { $OutputRoot = Join-Path $root "dist-windows-private" }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$trustedOutputParent = Get-WindowsPackagingOutputParent `
    -SourceRoot $root -OutputRoot $OutputRoot
$buildEnvironmentRoot = Join-Path $OutputRoot (".build-tools-" + [Guid]::NewGuid().ToString("N"))
$pythonExe = Join-Path $buildEnvironmentRoot "venv\Scripts\python.exe"
$nugetRoot = Join-Path $buildEnvironmentRoot "nuget"
$previousNugetPackages = $env:NUGET_PACKAGES
$project = Join-Path $root "windows\TVTimeRecovery.Windows\TVTimeRecovery.Windows.csproj"
$generatedContentRoot = Join-Path $OutputRoot "generated-content"
$helperDestination = Join-Path $generatedContentRoot "Helpers"
$assetDestination = Join-Path $generatedContentRoot "Assets"
$noticeDestination = Join-Path $generatedContentRoot "Notices"
$msbuildIntermediateRoot = (Join-Path $OutputRoot "obj") + [IO.Path]::DirectorySeparatorChar
$msbuildBinaryRoot = (Join-Path $OutputRoot "bin") + [IO.Path]::DirectorySeparatorChar
$helperDestinationOwnership = $null
$assetDestinationOwnership = $null
$noticeDestinationOwnership = $null
$noticeStageOwnership = $null
$noticeOutputOwnership = $null
$outputRootOwnership = $null
$buildEnvironmentOwnership = $null
$helperRootOwnership = $null
$nugetRootOwnership = $null
$helperManifest = $null
$packageIdentityPin = $null
$packageStrictPin = $null
$unsignedBlockMapDigest = $null
$outerError = $null
$packageResult = $null
try {
    if ($null -ne (Get-Item -LiteralPath $OutputRoot -Force -ErrorAction SilentlyContinue)) {
        throw "The private Windows build output must be fresh."
    }
    $env:NUGET_PACKAGES = $nugetRoot
    $helperBuildState = & (Join-Path $PSScriptRoot "build_windows_helper.ps1") `
        -Python $Python `
        -OutputRoot $OutputRoot `
        -BuildEnvironmentRoot $buildEnvironmentRoot `
        -PreserveBuildEnvironment `
        -ReturnBuildState
    if ($null -eq $helperBuildState -or
        $helperBuildState -is [array] -or
        $null -eq $helperBuildState.HelperRoot -or
        $null -eq $helperBuildState.OutputRootOwnership -or
        $null -eq $helperBuildState.BuildEnvironmentOwnership -or
        $null -eq $helperBuildState.HelperOwnership -or
        [string]::IsNullOrWhiteSpace([string]$helperBuildState.HelperManifest)) {
        throw "The private Windows helper returned an invalid build state."
    }
    $helperRoot = [string]$helperBuildState.HelperRoot
    $outputRootOwnership = $helperBuildState.OutputRootOwnership
    $buildEnvironmentOwnership = $helperBuildState.BuildEnvironmentOwnership
    $helperRootOwnership = $helperBuildState.HelperOwnership
    $helperManifest = [string]$helperBuildState.HelperManifest
    Assert-ContainedOrdinaryDirectoryOwnership `
        -OwnershipToken $outputRootOwnership | Out-Null
    if (Test-Path $helperDestination) { throw "The generated helper staging directory already exists." }
    if (Test-Path $assetDestination) { throw "The generated Windows asset staging directory already exists." }
    if (Test-Path $noticeDestination) { throw "The generated Windows notice staging directory already exists." }
    $buildError = $null
    try {
    Assert-ContainedOrdinaryDirectoryOwnership `
        -OwnershipToken $helperRootOwnership | Out-Null
    $helperDestinationOwnership = New-ContainedOrdinaryDirectory `
        -TrustedRoot $OutputRoot -Candidate $helperDestination `
        -TrustedRootOwnership $outputRootOwnership
    $helperMembers = @(Get-ChildItem -LiteralPath $helperRoot -Force)
    foreach ($helperMember in $helperMembers) {
        Copy-Item -LiteralPath $helperMember.FullName `
            -Destination $helperDestination -Recurse -Force
    }
    $helperDestinationOwnership = Convert-ContainedOrdinaryDirectoryToTreeSnapshot `
        -OwnershipToken $helperDestinationOwnership
    if ($helperDestinationOwnership.Manifest -cne $helperManifest) {
        throw "The copied Windows helper tree did not match its locked source manifest."
    }
    $assetDestinationOwnership = New-ContainedOrdinaryDirectory `
        -TrustedRoot $OutputRoot -Candidate $assetDestination `
        -TrustedRootOwnership $outputRootOwnership
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
    $assetDestinationOwnership = Convert-ContainedOrdinaryDirectoryToTreeSnapshot `
        -OwnershipToken $assetDestinationOwnership
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere -PathType Leaf)) { throw "A current Visual Studio installation with MSBuild and MSIX tooling is required." }
    $msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
    if (-not $msbuild) { throw "MSBuild was not found." }
    & $msbuild $project /t:Restore /p:RuntimeIdentifier=win-x64 /p:RestoreLockedMode=true `
        /p:RestorePackagesPath=$nugetRoot `
        /p:TVTimeGeneratedContentRoot=$generatedContentRoot `
        /p:BaseIntermediateOutputPath=$msbuildIntermediateRoot `
        /p:MSBuildProjectExtensionsPath=$msbuildIntermediateRoot `
        /p:BaseOutputPath=$msbuildBinaryRoot | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "The locked Windows dependency restore failed." }
    # Freeze the exact restored package graph before any validator consumes it.
    # Existing package bytes cannot be changed or replaced while the snapshot is
    # held; additions remain detectable by the post-consumer revalidation.
    $nugetRootOwnership = New-ContainedOrdinaryTreeSnapshot `
        -TrustedRoot $buildEnvironmentRoot -Candidate $nugetRoot
    Assert-ContainedOrdinaryDirectoryOwnership `
        -OwnershipToken $outputRootOwnership | Out-Null
    $noticeStage = Join-Path $OutputRoot (".notices-stage-" + [Guid]::NewGuid().ToString("N"))
    $noticeStageOwnership = New-ContainedOrdinaryDirectory `
        -TrustedRoot $OutputRoot -Candidate $noticeStage `
        -TrustedRootOwnership $outputRootOwnership
    $noticeStageOutput = Join-Path $noticeStage "Notices"
    $noticeOutputOwnership = New-ContainedOrdinaryDirectory `
        -TrustedRoot $noticeStage -Candidate $noticeStageOutput `
        -TrustedRootOwnership $noticeStageOwnership
    $dotnetVersion = (& dotnet --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $dotnetVersion -cne "8.0.423") {
        throw "The pinned .NET SDK 8.0.423 is required for the Windows package."
    }
    $sourceBindingArguments = @()
    if ($SourceCommit -or $SourceTree) {
        $sourceBindingArguments = @(
            "--source-commit", $SourceCommit,
            "--source-tree", $SourceTree
        )
    }
    & $pythonExe -B -I `
        (Join-Path $root "script\collect_windows_licenses.py") `
        --output $noticeStageOutput `
        --nuget-lock (Join-Path (Split-Path $project) "packages.lock.json") `
        --nuget-root $nugetRoot `
        --project-license (Join-Path $root "LICENSE") `
        --notice (Join-Path $root "windows\THIRD_PARTY_NOTICES.md") `
        @sourceBindingArguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "The private Windows license collection failed." }
    Assert-ContainedOrdinaryTreeSnapshot `
        -OwnershipToken $nugetRootOwnership | Out-Null
    $noticeOutputOwnership = Convert-ContainedOrdinaryDirectoryToTreeSnapshot `
        -OwnershipToken $noticeOutputOwnership
    $noticeDestinationOwnership = Move-ContainedOrdinaryDirectory `
        -OwnershipToken $noticeOutputOwnership `
        -DestinationTrustedRoot $OutputRoot `
        -Destination $noticeDestination
    $noticeOutputOwnership = $null
    $msixOutputDirectory = (Join-Path $OutputRoot "msix") + [IO.Path]::DirectorySeparatorChar
    $appxPackageDirectoryArgument = "/p:AppxPackageDir=$msixOutputDirectory"
    & $msbuild $project /m /p:Configuration=Release /p:Platform=x64 `
        /p:RuntimeIdentifier=win-x64 /p:GenerateAppxPackageOnBuild=true `
        /p:AppxPackageSigningEnabled=false /p:AppxBundle=Never `
        /p:RestoreLockedMode=true `
        /p:RestorePackagesPath=$nugetRoot `
        /p:TVTimeGeneratedContentRoot=$generatedContentRoot `
        /p:BaseIntermediateOutputPath=$msbuildIntermediateRoot `
        /p:MSBuildProjectExtensionsPath=$msbuildIntermediateRoot `
        /p:BaseOutputPath=$msbuildBinaryRoot `
        $appxPackageDirectoryArgument | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "The private Windows MSIX build failed." }
    Assert-ContainedOrdinaryTreeSnapshot `
        -OwnershipToken $nugetRootOwnership | Out-Null
    Release-ContainedOrdinaryDirectoryOwnership `
        -OwnershipToken $nugetRootOwnership
    $nugetRootOwnership = $null
} catch {
    $buildError = $_
} finally {
    Remove-ContainedOrdinaryTrees `
        -OwnershipTokens @(
            $helperDestinationOwnership,
            $assetDestinationOwnership,
            $noticeDestinationOwnership,
            $noticeOutputOwnership,
            $noticeStageOwnership
        ) `
        -PrimaryError $buildError
}
$packages = @(Get-ChildItem (Join-Path $OutputRoot "msix") -Filter *.msix -File -Recurse)
if ($packages.Count -ne 1) { throw "Expected exactly one x64 private MSIX package." }
$packagePath = [IO.Path]::GetFullPath($packages[0].FullName)
$packageIdentityPin = Open-PrivateMsixIdentityPin `
    -OutputRootOwnership $outputRootOwnership -Package $packagePath
$packageStrictPin = Open-PrivateMsixStrictReadPin `
    -OutputRootOwnership $outputRootOwnership `
    -Package $packagePath `
    -ExpectedIdentity $packageIdentityPin.Identity
$unsignedPackageSha256 = Get-PrivateMsixSha256 -PackageStream $packageStrictPin.Stream
$unsignedBlockMapDigest = Get-PrivateMsixBlockMapDigest `
    -PackageStream $packageStrictPin.Stream
Assert-ContainedOrdinaryDirectoryOwnership `
    -OwnershipToken $outputRootOwnership | Out-Null
$scanRoot = Join-Path $OutputRoot (".msix-scan-" + [Guid]::NewGuid().ToString("N"))
$scanRootOwnership = New-ContainedOrdinaryDirectory `
    -TrustedRoot $OutputRoot -Candidate $scanRoot `
    -TrustedRootOwnership $outputRootOwnership
$scanError = $null
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $scanRoot)
    $scanRootOwnership = Convert-ContainedOrdinaryDirectoryToTreeSnapshot `
        -OwnershipToken $scanRootOwnership
    $packagedHelper = Join-Path $scanRoot "Helpers"
    $packagedHelperManifest = `
        [TVTimeWindowsPackaging.DirectoryCapabilities]::ReadTreeManifest($packagedHelper)
    if ($packagedHelperManifest -cne $helperManifest) {
        throw "The packaged Windows helper tree did not match its locked source manifest."
    }
    $packagedAssetManifest = `
        [TVTimeWindowsPackaging.DirectoryCapabilities]::ReadTreeManifest(
            (Join-Path $scanRoot "Assets")
        )
    if ($packagedAssetManifest -cne $assetDestinationOwnership.Manifest) {
        throw "The packaged Windows asset tree did not match its locked source manifest."
    }
    $packagedNoticeManifest = `
        [TVTimeWindowsPackaging.DirectoryCapabilities]::ReadTreeManifest(
            (Join-Path $scanRoot "Notices")
        )
    if ($packagedNoticeManifest -cne $noticeDestinationOwnership.Manifest) {
        throw "The packaged Windows notice tree did not match its locked source manifest."
    }
    & $pythonExe -B -I `
        (Join-Path $root "script\scan_macos_release.py") --root $scanRoot --forbidden-value $root | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "The private Windows MSIX failed its privacy scan." }
    Assert-ContainedOrdinaryTreeSnapshot `
        -OwnershipToken $scanRootOwnership | Out-Null
} catch {
    $scanError = $_
} finally {
    Remove-ContainedOrdinaryTrees `
        -OwnershipTokens @($scanRootOwnership) `
        -PrimaryError $scanError
}
$packageResult = if ($ReturnBuildState) {
    [pscustomobject]@{
        Package = $packagePath
        PackageIdentityPin = $packageIdentityPin
        PackageIdentity = $packageIdentityPin.Identity
        UnsignedPackageSha256 = $unsignedPackageSha256
        UnsignedBlockMapDigest = $unsignedBlockMapDigest
        OutputRootOwnership = $outputRootOwnership
        HelperManifest = $helperManifest
    }
} else {
    $packagePath
}
Assert-ContainedOrdinaryDirectoryOwnership `
    -OwnershipToken $outputRootOwnership | Out-Null
if ($ReturnBuildState) {
    # Transfer these live capabilities to the installer. The strict read pin
    # closes before signing, while the overlapping identity pin continues to
    # deny delete/replace and permits SignTool's write access.
    $packageStrictPin.Dispose()
    $packageStrictPin = $null
    $packageIdentityPin = $null
    $outputRootOwnership = $null
}
} catch {
    $outerError = $_
} finally {
    if ($null -ne $packageStrictPin) {
        $packageStrictPin.Dispose()
        $packageStrictPin = $null
    }
    if ($null -ne $packageIdentityPin) {
        $packageIdentityPin.Dispose()
        $packageIdentityPin = $null
    }
    if ($previousNugetPackages) {
        $env:NUGET_PACKAGES = $previousNugetPackages
    } else {
        Remove-Item Env:NUGET_PACKAGES -ErrorAction SilentlyContinue
    }
    Release-ContainedOrdinaryDirectoryOwnership `
        -OwnershipToken $helperRootOwnership
    Release-ContainedOrdinaryDirectoryOwnership `
        -OwnershipToken $nugetRootOwnership
    if ($null -ne $outerError) {
        Remove-ContainedOrdinaryTrees `
            -OwnershipTokens @($buildEnvironmentOwnership, $outputRootOwnership) `
            -PrimaryError $outerError
    } else {
        try {
            Remove-ContainedOrdinaryTrees `
                -OwnershipTokens @($buildEnvironmentOwnership)
        } finally {
            if ($null -ne $outputRootOwnership) {
                Release-ContainedOrdinaryDirectoryOwnership `
                    -OwnershipToken $outputRootOwnership
            }
        }
    }
}
Write-Output $packageResult
