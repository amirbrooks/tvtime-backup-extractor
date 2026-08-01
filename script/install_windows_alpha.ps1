[CmdletBinding()]
param(
    [switch]$AcceptCertificateTrust,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$expectedSchema = "tvtime-windows-alpha-release-v1"
$expectedPackageIdentity = "AmirBrooks.TVTimeBackupExtractor.Alpha"
$expectedSubject = "CN=TV Time Backup Extractor Alpha"
$codeSigningOid = "1.3.6.1.5.5.7.3.3"
$root = [IO.Path]::GetFullPath($PSScriptRoot)

function Get-BoundArtifact {
    param(
        [Parameter(Mandatory = $true)][object]$Manifest,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $record = $Manifest.artifacts.$Label
    if ($null -eq $record -or
        $record.name -isnot [string] -or
        $record.sha256 -isnot [string] -or
        ($record.size -isnot [long] -and $record.size -isnot [int]) -or
        $record.name -notmatch '^[A-Za-z0-9][A-Za-z0-9._ -]{0,159}$' -or
        $record.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [long]$record.size -le 0) {
        throw "The Windows alpha manifest contained an invalid artifact binding."
    }
    $path = [IO.Path]::GetFullPath((Join-Path $root $record.name))
    if (-not $path.StartsWith(
        $root + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "A Windows alpha artifact escaped the downloaded bundle."
    }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -ne [long]$record.size) {
        throw "A Windows alpha artifact had an unsafe file shape."
    }
    $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($digest -cne $record.sha256) {
        throw "A Windows alpha artifact did not match its release manifest."
    }
    return $path
}

function Assert-ExactBundleMembership {
    param([Parameter(Mandatory = $true)][object]$Manifest)
    $expected = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    [void]$expected.Add("windows-release-manifest.json")
    foreach ($property in $Manifest.artifacts.PSObject.Properties) {
        if (-not $expected.Add([string]$property.Value.name)) {
            throw "The Windows alpha manifest contained an ambiguous artifact name."
        }
    }
    $observed = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($item in Get-ChildItem -LiteralPath $root -Force) {
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            -not $observed.Add($item.Name)) {
            throw "The Windows alpha bundle contained an unexpected file shape."
        }
    }
    if (-not $observed.SetEquals($expected)) {
        throw "The Windows alpha bundle contained unexpected files."
    }
}

function Assert-AlphaCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$ExpectedThumbprint
    )
    $ekuExtensions = @(
        $Certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
    )
    $keyUsageExtensions = @(
        $Certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.15" }
    )
    $basicConstraintsExtensions = @(
        $Certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
    )
    $matchingUsages = if ($ekuExtensions.Count -eq 1) {
        @($ekuExtensions[0].EnhancedKeyUsages | Where-Object { $_.Value -eq $codeSigningOid })
    } else {
        @()
    }
    if ($Certificate.Thumbprint -cne $ExpectedThumbprint -or
        $Certificate.Subject -cne $expectedSubject -or
        $Certificate.Issuer -cne $expectedSubject -or
        $Certificate.HasPrivateKey -or
        $Certificate.NotBefore -gt (Get-Date) -or
        $Certificate.NotAfter -le (Get-Date).AddDays(7) -or
        $ekuExtensions.Count -ne 1 -or
        $ekuExtensions[0].EnhancedKeyUsages.Count -ne 1 -or
        $matchingUsages.Count -ne 1 -or
        $keyUsageExtensions.Count -ne 1 -or
        $keyUsageExtensions[0].KeyUsages -ne
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -or
        $basicConstraintsExtensions.Count -ne 1 -or
        $basicConstraintsExtensions[0].CertificateAuthority) {
        throw "The Windows alpha signing certificate did not match the reviewed profile."
    }
}

function Invoke-AlphaCertificateTrust {
    param(
        [ValidateSet("Add", "Remove")][string]$Operation,
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [IO.FileStream]$TrustHelperPin,
        [ValidatePattern("^[A-Za-z0-9._-]{0,255}$")]
        [string]$PackageFullName = ""
    )
    $TrustHelperPin.Position = 0
    $reader = [IO.StreamReader]::new(
        $TrustHelperPin,
        [Text.Encoding]::UTF8,
        $true,
        4096,
        $true
    )
    try {
        $helperSource = $reader.ReadToEnd()
    } finally {
        $reader.Dispose()
    }
    $rawCertificateBase64 = [Convert]::ToBase64String($Certificate.RawData)
    $elevatedCommand = $helperSource + "`n" + @"
`$result = Set-PrivateWindowsCertificateTrust -Operation "$Operation" -Thumbprint "$($Certificate.Thumbprint)" -RawCertificateBase64 "$rawCertificateBase64" -PackageFullName "$PackageFullName"
exit `$result
"@
    $encodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($elevatedCommand)
    )
    $powerShell = Join-Path ([Environment]::GetFolderPath(
        [Environment+SpecialFolder]::Windows
    )) "System32\WindowsPowerShell\v1.0\powershell.exe"
    $process = Start-Process -FilePath $powerShell `
        -ArgumentList @("-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", $encodedCommand) `
        -Verb RunAs -Wait -PassThru
    if ($Operation -eq "Add" -and $process.ExitCode -in @(0, 10)) {
        return $process.ExitCode -eq 0
    }
    if ($Operation -eq "Remove" -and $process.ExitCode -in @(0, 11)) {
        return $process.ExitCode -eq 11
    }
    throw "Windows could not update the exact alpha signing certificate trust."
}

function Open-BoundArtifactReadPin {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Record
    )
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::None
    )
    try {
        if ($stream.Length -ne [long]$Record.size) {
            throw "A pinned Windows alpha artifact changed size."
        }
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = [BitConverter]::ToString($hasher.ComputeHash($stream)).Replace(
                "-", ""
            ).ToLowerInvariant()
        } finally {
            $hasher.Dispose()
        }
        if ($digest -cne [string]$Record.sha256) {
            throw "A pinned Windows alpha artifact changed after verification."
        }
        $stream.Position = 0
        return $stream
    } catch {
        $stream.Dispose()
        throw
    }
}

$manifestPath = Join-Path $root "windows-release-manifest.json"
$manifestItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
if ($manifestItem.PSIsContainer -or
    ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    $manifestItem.Length -le 0 -or $manifestItem.Length -gt 1MB) {
    throw "The Windows alpha release manifest was unavailable."
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.schema -cne $expectedSchema -or
    $manifest.release.channel -cne "experimental-alpha" -or
    $manifest.release.architecture -cne "x64" -or
    $manifest.release.package_identity -cne $expectedPackageIdentity -or
    $manifest.signing.kind -cne "ephemeral-self-signed-alpha" -or
    $manifest.signing.private_key_included -ne $false -or
    $manifest.signing.certificate_thumbprint -notmatch '^[0-9A-F]{40}$') {
    throw "The Windows alpha release manifest had an unsupported identity."
}

Assert-ExactBundleMembership -Manifest $manifest
$package = Get-BoundArtifact -Manifest $manifest -Label "package"
$certificatePath = Get-BoundArtifact -Manifest $manifest -Label "certificate"
$trustHelper = Get-BoundArtifact -Manifest $manifest -Label "trust_helper"
$trustHelperPin = Open-BoundArtifactReadPin `
    -Path $trustHelper -Record $manifest.artifacts.trust_helper
foreach ($label in @("installer", "uninstaller", "readme", "license", "third_party_notices")) {
    [void](Get-BoundArtifact -Manifest $manifest -Label $label)
}

$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
    [IO.File]::ReadAllBytes($certificatePath)
)
Assert-AlphaCertificate `
    -Certificate $certificate `
    -ExpectedThumbprint ([string]$manifest.signing.certificate_thumbprint)
$signature = Get-AuthenticodeSignature -FilePath $package
if ($null -eq $signature.SignerCertificate -or
    $signature.SignerCertificate.Thumbprint -cne $certificate.Thumbprint) {
    throw "The Windows alpha package signature did not match its bundled certificate."
}

$installed = @(Get-AppxPackage -Name $expectedPackageIdentity -ErrorAction Stop)
if ($installed.Count -ne 0) {
    throw "This Windows alpha is already installed. Preserve any recovered reports before removing or replacing it."
}
if (-not $AcceptCertificateTrust) {
    if ($NonInteractive) {
        throw "Certificate trust requires explicit acceptance."
    }
    Write-Host "This experimental build uses a project-specific self-signed certificate."
    Write-Host "Windows will request permission to trust that public certificate for this alpha."
    $confirmation = Read-Host "Type INSTALL to continue"
    if ($confirmation -cne "INSTALL") {
        throw "Windows alpha installation was cancelled."
    }
}

$certificateAdded = Invoke-AlphaCertificateTrust `
    -Operation "Add" -Certificate $certificate -TrustHelperPin $trustHelperPin
try {
    $trustedSignature = Get-AuthenticodeSignature -FilePath $package
    if ($trustedSignature.Status -ne "Valid" -or
        $trustedSignature.SignerCertificate.Thumbprint -cne $certificate.Thumbprint) {
        throw "Windows did not validate the exact alpha package signature."
    }
    Add-AppxPackage -Path $package -ForceApplicationShutdown
    $installedAfter = @(Get-AppxPackage -Name $expectedPackageIdentity -ErrorAction Stop)
    if ($installedAfter.Count -ne 1 -or
        $installedAfter[0].Publisher -cne $expectedSubject) {
        throw "Windows did not register the exact alpha package identity."
    }
} catch {
    $installationError = $_
    $cleanupFailed = $false
    $cleanupPackages = @(Get-AppxPackage -Name $expectedPackageIdentity -ErrorAction SilentlyContinue |
        Where-Object { $_.Publisher -ceq $expectedSubject })
    foreach ($cleanupPackage in $cleanupPackages) {
        try {
            Remove-AppxPackage -Package $cleanupPackage.PackageFullName -Confirm:$false
        } catch {
            $cleanupFailed = $true
        }
    }
    if ($certificateAdded) {
        try {
            [void](Invoke-AlphaCertificateTrust `
                -Operation "Remove" -Certificate $certificate -TrustHelperPin $trustHelperPin)
        } catch {
            $cleanupFailed = $true
        }
    }
    if ($cleanupFailed) {
        throw "Installation failed and exact package or certificate cleanup also failed. Use only the identities recorded in the release manifest for manual cleanup."
    }
    throw $installationError
} finally {
    $trustHelperPin.Dispose()
    $certificate.Dispose()
}

Write-Output "TV Time Backup Extractor Windows alpha installed for the current user."
