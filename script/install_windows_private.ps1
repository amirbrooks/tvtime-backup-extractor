[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "windows_packaging_lib.ps1")
. (Join-Path $PSScriptRoot "windows_msix_integrity.ps1")

function Invoke-LocalMachineCertificateTrust {
    param(
        [ValidateSet("Add", "Remove")]
        [string]$Operation,
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $thumbprint = $Certificate.Thumbprint
    $rawCertificateBase64 = [Convert]::ToBase64String($Certificate.RawData)
    if ($thumbprint -cnotmatch "^[A-F0-9]{40}$" -or
        $rawCertificateBase64.Length -gt 4096 -or
        $rawCertificateBase64 -cnotmatch "^[A-Za-z0-9+/]+={0,2}$") {
        throw "The private package certificate could not be passed to the trust helper."
    }
    $helperPath = Join-Path $PSScriptRoot "windows_certificate_trust.ps1"
    $expectedTrustHelperSha256 = "BCC1A071014879565F1ECFB58FA92417E564B87E5C26E02DE6165DF3901FB10F"
    $helperBytes = [IO.File]::ReadAllBytes($helperPath)
    if ($helperBytes.Length -eq 0 -or $helperBytes.Length -gt 16KB) {
        throw "The private package certificate trust helper has invalid size."
    }
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $actualTrustHelperSha256 = [BitConverter]::ToString(
            $sha256.ComputeHash($helperBytes)
        ).Replace("-", "")
    } finally {
        $sha256.Dispose()
    }
    if ($actualTrustHelperSha256 -cne $expectedTrustHelperSha256) {
        throw "The private package certificate trust helper changed after review."
    }
    $strictUtf8 = New-Object Text.UTF8Encoding($false, $true)
    $helperSource = $strictUtf8.GetString($helperBytes)
    $elevatedCommand = $helperSource + "`n" + @"
`$result = Set-PrivateWindowsCertificateTrust -Operation "$Operation" -Thumbprint "$thumbprint" -RawCertificateBase64 "$rawCertificateBase64"
exit `$result
"@
    $encodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($elevatedCommand)
    )
    $windowsDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::Windows
    )
    $powerShellExecutable = Join-Path $windowsDirectory `
        "System32\WindowsPowerShell\v1.0\powershell.exe"
    $powerShellItem = Get-Item -LiteralPath $powerShellExecutable -Force
    if (-not $powerShellItem.PSIsContainer -and
        -not ($powerShellItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        $powerShellExecutable = $powerShellItem.FullName
    } else {
        throw "The protected Windows PowerShell executable could not be resolved."
    }
    $unresolvedTrustMessage = "Windows could not prove removal of the exact private package certificate from LocalMachine\TrustedPeople. Machine trust may remain; before retrying, remove only the app-specific certificate whose thumbprint matches the allowed CurrentUser\My signer."
    try {
        $elevatedProcess = Start-Process -FilePath $powerShellExecutable `
            -ArgumentList @("-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", $encodedCommand) `
            -Verb RunAs -Wait -PassThru
    } catch {
        throw $unresolvedTrustMessage
    }
    if ($Operation -eq "Add") {
        if ($elevatedProcess.ExitCode -eq 0) { return $true }
        if ($elevatedProcess.ExitCode -eq 10) { return $false }
        if ($elevatedProcess.ExitCode -eq 20) {
            throw "Windows could not update the exact private package certificate trust."
        }
    } elseif ($elevatedProcess.ExitCode -eq 0) {
        return
    }
    throw $unresolvedTrustMessage
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$installed = @(Get-AppxPackage -Name "AmirBrooks.TVTimeBackupExtractor.Private" -ErrorAction Stop)
if ($installed.Count -ne 0) {
    throw "The private package is already installed. Review retained private output before any manual uninstall or versioned update; this installer never removes app data."
}

$buildState = $null
$outputRootOwnership = $null
$packageIdentityPin = $null
$packageStrictPin = $null
try {
    $buildState = & (Join-Path $PSScriptRoot "build_windows_app.ps1") -ReturnBuildState
    if ($null -eq $buildState -or $buildState -is [array] -or
        [string]::IsNullOrWhiteSpace([string]$buildState.Package) -or
        $null -eq $buildState.PackageIdentityPin -or
        [string]::IsNullOrWhiteSpace([string]$buildState.PackageIdentity) -or
        [string]::IsNullOrWhiteSpace([string]$buildState.UnsignedPackageSha256) -or
        [string]::IsNullOrWhiteSpace([string]$buildState.UnsignedBlockMapDigest) -or
        $null -eq $buildState.OutputRootOwnership -or
        [string]::IsNullOrWhiteSpace([string]$buildState.HelperManifest)) {
        throw "The private Windows build returned an invalid capability state."
    }

    $Package = [IO.Path]::GetFullPath([string]$buildState.Package)
    if (-not $Package.StartsWith(
        $root + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Only a freshly built private package beneath this repository may be installed."
    }
    $packageIdentityPin = $buildState.PackageIdentityPin
    $outputRootOwnership = $buildState.OutputRootOwnership
    if ($packageIdentityPin.Identity -cne [string]$buildState.PackageIdentity) {
        throw "The private Windows build returned mismatched package identity state."
    }
    Assert-ContainedOrdinaryDirectoryOwnership `
        -OwnershipToken $outputRootOwnership | Out-Null

    # Reacquire a strict read lock while the build's signer-compatible identity
    # pin is still live, and verify the exact block map that passed the build
    # scan before any signing write is allowed.
    $packageStrictPin = Open-PrivateMsixStrictReadPin `
        -OutputRootOwnership $outputRootOwnership `
        -Package $Package `
        -ExpectedIdentity ([string]$buildState.PackageIdentity)
    $preSignPackageSha256 = Get-PrivateMsixSha256 `
        -PackageStream $packageStrictPin.Stream
    $preSignBlockMapDigest = Get-PrivateMsixBlockMapDigest `
        -PackageStream $packageStrictPin.Stream
    if ($preSignPackageSha256 -cne [string]$buildState.UnsignedPackageSha256 -or
        $preSignBlockMapDigest -cne [string]$buildState.UnsignedBlockMapDigest) {
        throw "The private MSIX payload changed after its build scan."
    }

    $subject = "CN=TV Time Backup Extractor Private"
    $friendlyName = "TV Time Recovery private local install"
    $codeSigningOid = "1.3.6.1.5.5.7.3.3"
    $certificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        $candidate = $_
        $ekuExtensions = @(
            $candidate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
        )
        $keyUsageExtensions = @(
            $candidate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.15" }
        )
        $basicConstraintsExtensions = @(
            $candidate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
        )
        $hasExactCodeSigningUsage = $false
        if ($ekuExtensions.Count -eq 1) {
            $matchingUsages = @(
                $ekuExtensions[0].EnhancedKeyUsages | Where-Object {
                    $_.Value -eq $codeSigningOid
                }
            )
            $hasExactCodeSigningUsage = (
                $matchingUsages.Count -eq 1 -and
                $ekuExtensions[0].EnhancedKeyUsages.Count -eq 1 -and
                $keyUsageExtensions.Count -eq 1 -and
                $keyUsageExtensions[0].KeyUsages -eq
                    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -and
                $basicConstraintsExtensions.Count -eq 1 -and
                -not $basicConstraintsExtensions[0].CertificateAuthority
            )
        }
        $candidate.Subject -eq $subject -and
            $candidate.Issuer -eq $subject -and
            $candidate.FriendlyName -eq $friendlyName -and
            $candidate.NotBefore -le (Get-Date) -and
            $candidate.NotAfter -gt (Get-Date).AddDays(30) -and
            $candidate.HasPrivateKey -and
            $hasExactCodeSigningUsage
    } | Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $certificate) {
        $certificate = New-SelfSignedCertificate -Type Custom -Subject $subject `
            -KeyUsage DigitalSignature -FriendlyName $friendlyName `
            -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(2) `
            -TextExtension @("2.5.29.37={text}$codeSigningOid", "2.5.29.19={text}")
    }
    $signTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
        -Filter signtool.exe -File -Recurse |
        Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signTool) { throw "The Windows SDK signing tool was not found." }

    # The identity pin remains open while the strict read pin closes, so the
    # path cannot be replaced while SignTool receives write access.
    $packageStrictPin.Dispose()
    $packageStrictPin = $null
    & $signTool.FullName sign /fd SHA256 /sha1 $certificate.Thumbprint /s My $Package
    if ($LASTEXITCODE -ne 0) { throw "The private MSIX could not be signed." }

    # Acquire the install-time no-write/no-delete pin before releasing the
    # overlapping identity pin. Any concurrent writer makes this fail closed.
    $packageStrictPin = Open-PrivateMsixStrictReadPin `
        -OutputRootOwnership $outputRootOwnership `
        -Package $Package `
        -ExpectedIdentity ([string]$buildState.PackageIdentity)
    $packageIdentityPin.Dispose()
    $packageIdentityPin = $null
    $signedBlockMapDigest = Get-PrivateMsixBlockMapDigest `
        -PackageStream $packageStrictPin.Stream
    if ($signedBlockMapDigest -cne [string]$buildState.UnsignedBlockMapDigest) {
        throw "Signing changed the reviewed private MSIX payload."
    }
    Assert-ContainedOrdinaryDirectoryOwnership `
        -OwnershipToken $outputRootOwnership | Out-Null

    $publicCertificate = New-Object `
        System.Security.Cryptography.X509Certificates.X509Certificate2($certificate.RawData)
    $trustedCertificateAdded = Invoke-LocalMachineCertificateTrust `
        -Operation "Add" -Certificate $publicCertificate

    $installationError = $null
    try {
        & $signTool.FullName verify /pa /v $Package
        if ($LASTEXITCODE -ne 0) {
            throw "The private MSIX signature could not be verified."
        }
        $packageSignature = Get-AuthenticodeSignature -FilePath $Package
        if ($packageSignature.Status -ne "Valid" -or
            $packageSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
            throw "The private MSIX was not signed by the exact reviewed private certificate."
        }
        # The strict package stream remains open here. Add-AppxPackage may read
        # the file, but no process can write, delete, or replace these bytes.
        Add-AppxPackage -Path $Package -ForceApplicationShutdown
    } catch {
        $installationError = $_
    }
    if ($null -ne $installationError) {
        if ($trustedCertificateAdded) {
            $cleanupError = $null
            try {
                Invoke-LocalMachineCertificateTrust `
                    -Operation "Remove" -Certificate $publicCertificate
            } catch {
                $cleanupError = $_
            }
            if ($null -ne $cleanupError) {
                $combinedMessage = "The private installation failed and automatic machine certificate cleanup did not complete. Machine trust may remain; before retrying, remove only the LocalMachine\TrustedPeople certificate whose thumbprint matches the allowed CurrentUser\My signer. The original installation failure is retained as this error's cause."
                $combinedError = New-Object `
                    -TypeName System.InvalidOperationException `
                    -ArgumentList $combinedMessage, $installationError.Exception
                throw $combinedError
            }
        }
        throw $installationError
    }
} finally {
    if ($null -ne $packageStrictPin) { $packageStrictPin.Dispose() }
    if ($null -ne $packageIdentityPin) { $packageIdentityPin.Dispose() }
    if ($null -ne $outputRootOwnership) {
        Release-ContainedOrdinaryDirectoryOwnership `
            -OwnershipToken $outputRootOwnership
    }
}

Write-Output "Private per-user installation completed. No package was uploaded or published."
