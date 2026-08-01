[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceCommit,
    [Parameter(Mandatory = $true)][string]$ReleaseVersion,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)

function Assert-NativeSuccess([string]$Message) {
    if ($LASTEXITCODE -ne 0) { throw $Message }
}

$pythonExecutable = (Get-Command $Python -CommandType Application -ErrorAction Stop).Source
$gitExecutable = (Get-Command git -CommandType Application -ErrorAction Stop).Source
if ([Environment]::GetEnvironmentVariable(
    "TVTIME_IMMUTABLE_WINDOWS_RELEASE_SOURCE",
    "Process"
) -cne "1") {
    if ($SourceCommit -notmatch '^[0-9a-f]{40}$') {
        throw "The Windows release source commit was invalid."
    }
    $actualCommit = (& $gitExecutable -C $scriptRoot rev-parse 'HEAD^{commit}').Trim()
    Assert-NativeSuccess "The Windows release checkout commit could not be inspected."
    if ($actualCommit -cne $SourceCommit) {
        throw "The Windows release source commit did not match the checkout."
    }
    if ((& $gitExecutable -C $scriptRoot status --porcelain=v1 --untracked-files=all) -join "") {
        throw "The Windows release checkout must be completely clean."
    }
    $sourceStageObject = "${SourceCommit}:script/git_source_stage.py"
    $preparedStage = (
        & $gitExecutable -C $scriptRoot show $sourceStageObject |
            & $pythonExecutable -I - `
                --prepare --repository $scriptRoot --source-commit $SourceCommit
    ).Trim()
    Assert-NativeSuccess "The reviewed Windows release source could not be staged."
    $preparedStage = [IO.Path]::GetFullPath($preparedStage)
    $stagedSource = Join-Path $preparedStage "source"
    $stagedBuilder = Join-Path $stagedSource "script\build_windows_release.ps1"
    if (-not (Test-Path -LiteralPath $stagedBuilder -PathType Leaf)) {
        & $pythonExecutable -I (Join-Path $stagedSource "script\git_source_stage.py") `
            --remove --repository $scriptRoot --source $stagedSource | Out-Null
        throw "The staged Windows release builder was unavailable."
    }
    $environmentNames = @(
        "TVTIME_IMMUTABLE_WINDOWS_RELEASE_SOURCE",
        "TVTIME_WINDOWS_RELEASE_CHECKOUT_ROOT",
        "TVTIME_WINDOWS_PREPARED_RELEASE_STAGE"
    )
    $previousEnvironment = @{}
    foreach ($name in $environmentNames) {
        $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    try {
        [Environment]::SetEnvironmentVariable(
            "TVTIME_IMMUTABLE_WINDOWS_RELEASE_SOURCE", "1", "Process"
        )
        [Environment]::SetEnvironmentVariable(
            "TVTIME_WINDOWS_RELEASE_CHECKOUT_ROOT", $scriptRoot, "Process"
        )
        [Environment]::SetEnvironmentVariable(
            "TVTIME_WINDOWS_PREPARED_RELEASE_STAGE", $preparedStage, "Process"
        )
        & $stagedBuilder `
            -SourceCommit $SourceCommit `
            -ReleaseVersion $ReleaseVersion `
            -OutputRoot $OutputRoot `
            -Python $pythonExecutable
    } finally {
        foreach ($name in $environmentNames) {
            [Environment]::SetEnvironmentVariable(
                $name, $previousEnvironment[$name], "Process"
            )
        }
    }
    return
}

$root = $scriptRoot
$checkoutRoot = [IO.Path]::GetFullPath([Environment]::GetEnvironmentVariable(
    "TVTIME_WINDOWS_RELEASE_CHECKOUT_ROOT",
    "Process"
))
$stageRoot = [IO.Path]::GetFullPath([Environment]::GetEnvironmentVariable(
    "TVTIME_WINDOWS_PREPARED_RELEASE_STAGE",
    "Process"
))
$source = $root
$expectedSource = Join-Path $stageRoot "source"
if ($source -cne $expectedSource -or -not (Test-Path -LiteralPath $source -PathType Container)) {
    throw "The Windows release builder was not running from its reviewed source stage."
}
$buildState = $null
$packageStrictPin = $null
$certificate = $null
$temporaryTrustStore = $null
$publicCertificate = $null
$bodyError = $null

try {
    if ($SourceCommit -notmatch '^[0-9a-f]{40}$') {
        throw "The Windows release source commit was invalid."
    }
    $actualCommit = (& $gitExecutable -C $checkoutRoot rev-parse 'HEAD^{commit}').Trim()
    Assert-NativeSuccess "The Windows release checkout commit could not be inspected."
    if ($actualCommit -cne $SourceCommit) {
        throw "The Windows release source commit did not match the checkout."
    }
    if ((& $gitExecutable -C $checkoutRoot status --porcelain=v1 --untracked-files=all) -join "") {
        throw "The Windows release checkout must be completely clean."
    }
    $sourceTree = (& $gitExecutable -C $checkoutRoot rev-parse "$SourceCommit^{tree}").Trim()
    Assert-NativeSuccess "The Windows release source tree could not be inspected."
    if ($sourceTree -notmatch '^[0-9a-f]{40}$') {
        throw "The Windows release source tree was invalid."
    }
    & $pythonExecutable -I (Join-Path $root "script\git_source_stage.py") `
        --verify --repository $checkoutRoot --source-commit $SourceCommit --source $source |
        Out-Host
    Assert-NativeSuccess "The reviewed Windows release source stage was invalid."
    $expectedPythonVersion = (& $pythonExecutable -I `
        (Join-Path $root "script\release_version.py") `
        $ReleaseVersion --format python).Trim()
    Assert-NativeSuccess "The Windows alpha version could not be translated for Python."
    $stagedScript = Join-Path $source "script\build_windows_app.ps1"
    if (-not (Test-Path -LiteralPath $stagedScript -PathType Leaf)) {
        throw "The staged Windows release builder was unavailable."
    }
    if (Test-Path -LiteralPath $OutputRoot) {
        throw "The Windows release output must be fresh."
    }
    New-Item -ItemType Directory -Path $OutputRoot -ErrorAction Stop | Out-Null

    $privateOutput = Join-Path $source ".build-tools\windows-release-private"
    $buildState = & $stagedScript `
        -OutputRoot $privateOutput `
        -Python $pythonExecutable `
        -SourceCommit $SourceCommit `
        -SourceTree $sourceTree `
        -ReturnBuildState
    if ($null -eq $buildState -or $buildState -is [array] -or
        [string]::IsNullOrWhiteSpace([string]$buildState.Package) -or
        $null -eq $buildState.PackageIdentityPin -or
        [string]::IsNullOrWhiteSpace([string]$buildState.PackageIdentity) -or
        [string]::IsNullOrWhiteSpace([string]$buildState.UnsignedPackageSha256) -or
        [string]::IsNullOrWhiteSpace([string]$buildState.UnsignedBlockMapDigest) -or
        $null -eq $buildState.OutputRootOwnership) {
        throw "The Windows release builder returned an invalid capability state."
    }

    . (Join-Path $source "script\windows_packaging_lib.ps1")
    . (Join-Path $source "script\windows_msix_integrity.ps1")
    $package = [IO.Path]::GetFullPath([string]$buildState.Package)
    $packageStrictPin = Open-PrivateMsixStrictReadPin `
        -OutputRootOwnership $buildState.OutputRootOwnership `
        -Package $package `
        -ExpectedIdentity ([string]$buildState.PackageIdentity)
    $preSignSha256 = Get-PrivateMsixSha256 -PackageStream $packageStrictPin.Stream
    $preSignBlockMap = Get-PrivateMsixBlockMapDigest -PackageStream $packageStrictPin.Stream
    if ($preSignSha256 -cne [string]$buildState.UnsignedPackageSha256 -or
        $preSignBlockMap -cne [string]$buildState.UnsignedBlockMapDigest) {
        throw "The Windows alpha package changed before signing."
    }

    $subject = "CN=TV Time Backup Extractor Alpha"
    $friendlyName = "TV Time Recovery ephemeral alpha signer"
    $codeSigningOid = "1.3.6.1.5.5.7.3.3"
    $certificate = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $subject `
        -KeyUsage DigitalSignature `
        -FriendlyName $friendlyName `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddYears(1) `
        -TextExtension @("2.5.29.37={text}$codeSigningOid", "2.5.29.19={text}")
    if ($null -eq $certificate -or -not $certificate.HasPrivateKey) {
        throw "The Windows alpha signing certificate could not be created."
    }
    $signTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
        -Filter signtool.exe -File -Recurse |
        Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signTool) {
        throw "The Windows SDK signing tool was unavailable."
    }
    $packageStrictPin.Dispose()
    $packageStrictPin = $null
    & $signTool.FullName sign /fd SHA256 /sha1 $certificate.Thumbprint /s My $package | Out-Host
    Assert-NativeSuccess "The Windows alpha package could not be signed."

    $packageStrictPin = Open-PrivateMsixStrictReadPin `
        -OutputRootOwnership $buildState.OutputRootOwnership `
        -Package $package `
        -ExpectedIdentity ([string]$buildState.PackageIdentity)
    $buildState.PackageIdentityPin.Dispose()
    $buildState.PackageIdentityPin = $null
    $signedBlockMap = Get-PrivateMsixBlockMapDigest -PackageStream $packageStrictPin.Stream
    if ($signedBlockMap -cne [string]$buildState.UnsignedBlockMapDigest) {
        throw "Signing changed the reviewed Windows alpha payload."
    }

    $publicCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $certificate.RawData
    )
    $temporaryTrustStore = [Security.Cryptography.X509Certificates.X509Store]::new(
        "TrustedPeople",
        "CurrentUser"
    )
    $temporaryTrustStore.Open(
        [Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite
    )
    $temporaryTrustStore.Add($publicCertificate)
    & $signTool.FullName verify /pa /v $package | Out-Host
    Assert-NativeSuccess "The Windows alpha package signature could not be verified."
    $signature = Get-AuthenticodeSignature -FilePath $package
    if ($signature.Status -ne "Valid" -or
        $signature.SignerCertificate.Thumbprint -cne $certificate.Thumbprint) {
        throw "The Windows alpha package signature did not match the ephemeral signer."
    }

    $artifactBase = "TV-Time-Backup-Extractor-$ReleaseVersion-Windows-x64"
    $bundleRoot = Join-Path $OutputRoot $artifactBase
    New-Item -ItemType Directory -Path $bundleRoot -ErrorAction Stop | Out-Null
    $packageDestination = Join-Path $bundleRoot "$artifactBase.msix"
    $packageOutput = [IO.File]::Open(
        $packageDestination,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $packageStrictPin.Stream.Position = 0
        $packageStrictPin.Stream.CopyTo($packageOutput)
        $packageOutput.Flush($true)
    } finally {
        $packageOutput.Dispose()
    }
    $certificateDestination = Join-Path $bundleRoot "$artifactBase.cer"
    [IO.File]::WriteAllBytes($certificateDestination, $publicCertificate.RawData)

    $installer = Join-Path $bundleRoot "Install-Windows-Alpha.ps1"
    $uninstaller = Join-Path $bundleRoot "Uninstall-Windows-Alpha.ps1"
    $trustHelper = Join-Path $bundleRoot "Windows-Certificate-Trust.ps1"
    $readme = Join-Path $bundleRoot "README.txt"
    $license = Join-Path $bundleRoot "LICENSE.txt"
    $notices = Join-Path $bundleRoot "THIRD-PARTY-NOTICES.txt"
    Copy-Item -LiteralPath (Join-Path $source "script\install_windows_alpha.ps1") `
        -Destination $installer
    Copy-Item -LiteralPath (Join-Path $source "script\uninstall_windows_alpha.ps1") `
        -Destination $uninstaller
    Copy-Item -LiteralPath (Join-Path $source "script\windows_certificate_trust.ps1") `
        -Destination $trustHelper
    Copy-Item -LiteralPath (Join-Path $source "windows\WINDOWS_ALPHA_README.txt") `
        -Destination $readme
    Copy-Item -LiteralPath (Join-Path $source "LICENSE") -Destination $license
    Copy-Item -LiteralPath (Join-Path $source "windows\THIRD_PARTY_NOTICES.md") `
        -Destination $notices

    $pythonVersion = (& $pythonExecutable -I -c `
        "import sys; print('.'.join(map(str, sys.version_info[:3])))").Trim()
    Assert-NativeSuccess "The Windows alpha Python version could not be inspected."
    if ($pythonVersion -cne "3.13.12" -or $expectedPythonVersion -cne "0.3.1a1") {
        throw "The Windows alpha used an unexpected Python version."
    }
    $dotnetSdkVersion = (& dotnet --version).Trim()
    Assert-NativeSuccess "The Windows alpha .NET SDK version could not be inspected."
    $manifest = Join-Path $bundleRoot "windows-release-manifest.json"
    & $pythonExecutable -I (Join-Path $source "script\generate_windows_release_manifest.py") `
        --release-version $ReleaseVersion `
        --source-commit $SourceCommit `
        --source-tree $sourceTree `
        --package-identity "AmirBrooks.TVTimeBackupExtractor.Alpha" `
        --certificate-thumbprint $certificate.Thumbprint `
        --unsigned-package-sha256 ([string]$buildState.UnsignedPackageSha256) `
        --block-map-sha256 $signedBlockMap `
        --python-version $pythonVersion `
        --dotnet-sdk-version $dotnetSdkVersion `
        --source-root $source `
        --package $packageDestination `
        --certificate $certificateDestination `
        --installer $installer `
        --uninstaller $uninstaller `
        --trust-helper $trustHelper `
        --readme $readme `
        --license $license `
        --third-party-notices $notices `
        --output $manifest | Out-Host
    Assert-NativeSuccess "The Windows alpha release manifest could not be generated."

    & $pythonExecutable -I (Join-Path $source "script\scan_macos_release.py") `
        --root $bundleRoot `
        --forbidden-value $root `
        --forbidden-value $checkoutRoot `
        --forbidden-value $source | Out-Host
    Assert-NativeSuccess "The Windows alpha bundle failed its privacy scan."

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $bundle = Join-Path $OutputRoot "$artifactBase.zip"
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $bundleRoot,
        $bundle,
        [IO.Compression.CompressionLevel]::Optimal,
        $false
    )
    & $pythonExecutable -I (Join-Path $source "script\verify_windows_release.py") `
        --bundle $bundle `
        --release-version $ReleaseVersion `
        --source-commit $SourceCommit `
        --source-tree $sourceTree | Out-Host
    Assert-NativeSuccess "The Windows alpha bundle failed release verification."

    $publishedManifest = Join-Path $OutputRoot "windows-release-manifest.json"
    Copy-Item -LiteralPath $manifest -Destination $publishedManifest
    $checksums = Join-Path $OutputRoot "SHA256SUMS-Windows"
    $bundleHash = (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifestHash = (Get-FileHash -LiteralPath $publishedManifest -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        $checksums,
        "$bundleHash  $([IO.Path]::GetFileName($bundle))`n$manifestHash  $([IO.Path]::GetFileName($publishedManifest))`n",
        [Text.UTF8Encoding]::new($false)
    )
    & $pythonExecutable -I (Join-Path $source "script\git_source_stage.py") `
        --verify --repository $checkoutRoot --source-commit $SourceCommit --source $source |
        Out-Host
    Assert-NativeSuccess "The Windows release source stage changed during the build."
    $finalCommit = (& $gitExecutable -C $checkoutRoot rev-parse 'HEAD^{commit}').Trim()
    Assert-NativeSuccess "The final Windows release checkout commit could not be inspected."
    $finalTree = (& $gitExecutable -C $checkoutRoot rev-parse "$SourceCommit^{tree}").Trim()
    Assert-NativeSuccess "The final Windows release checkout tree could not be inspected."
    $finalStatus = (
        & $gitExecutable -C $checkoutRoot status --porcelain=v1 --untracked-files=all
    ) -join ""
    if ($finalCommit -cne $SourceCommit -or $finalTree -cne $sourceTree -or $finalStatus) {
        throw "The Windows release checkout changed during the build."
    }
    Write-Output ([pscustomobject]@{
        Bundle = $bundle
        Manifest = $publishedManifest
        Checksums = $checksums
        SourceCommit = $SourceCommit
        SourceTree = $sourceTree
    })
} catch {
    $bodyError = $_
} finally {
    if ($null -ne $temporaryTrustStore -and $null -ne $publicCertificate) {
        try {
            $temporaryTrustStore.Remove($publicCertificate)
            $remainingTemporaryTrust = @(
                $temporaryTrustStore.Certificates | Where-Object {
                    $_.Thumbprint -ceq $publicCertificate.Thumbprint
                }
            )
            if ($remainingTemporaryTrust.Count -ne 0) {
                throw "The temporary Windows alpha trust remained after the build."
            }
        } catch {
            if ($null -eq $bodyError) {
                $bodyError = $_
            } else {
                $bodyError = [InvalidOperationException]::new(
                    "The Windows alpha build failed and temporary trust cleanup also failed.",
                    $bodyError.Exception
                )
            }
        }
        $temporaryTrustStore.Dispose()
    }
    if ($null -ne $packageStrictPin) { $packageStrictPin.Dispose() }
    if ($null -ne $buildState) {
        if ($null -ne $buildState.PackageIdentityPin) {
            $buildState.PackageIdentityPin.Dispose()
        }
        if ($null -ne $buildState.OutputRootOwnership) {
            Release-ContainedOrdinaryDirectoryOwnership `
                -OwnershipToken $buildState.OutputRootOwnership
        }
    }
    if ($null -ne $certificate) {
        $privateCertificatePath = "Cert:\CurrentUser\My\$($certificate.Thumbprint)"
        try {
            if (Test-Path -LiteralPath $privateCertificatePath) {
                Remove-Item -Path $privateCertificatePath -DeleteKey -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $privateCertificatePath) {
                throw "The ephemeral Windows alpha private key remained after the build."
            }
        } catch {
            if ($null -eq $bodyError) {
                $bodyError = $_
            } else {
                $bodyError = [InvalidOperationException]::new(
                    "The Windows alpha build failed and ephemeral signer cleanup also failed.",
                    $bodyError.Exception
                )
            }
        }
    }
    if ($null -ne $publicCertificate) { $publicCertificate.Dispose() }
    if ($null -ne $certificate) { $certificate.Dispose() }
    if ($null -ne $stageRoot -and $null -ne $source) {
        & $pythonExecutable -I (Join-Path $root "script\git_source_stage.py") `
            --remove --repository $checkoutRoot --source $source | Out-Null
        if ($LASTEXITCODE -ne 0) {
            if ($null -eq $bodyError) {
                $bodyError = [InvalidOperationException]::new(
                    "The Windows release source stage could not be removed."
                )
            } else {
                $bodyError = [InvalidOperationException]::new(
                    "The Windows alpha build failed and source-stage cleanup also failed.",
                    $bodyError.Exception
                )
            }
        }
    }
    if ($null -ne $bodyError) { throw $bodyError }
}
