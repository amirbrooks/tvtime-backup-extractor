[CmdletBinding()]
param(
    [switch]$ConfirmRemoval,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$expectedIdentity = "AmirBrooks.TVTimeBackupExtractor.Alpha"
$expectedSubject = "CN=TV Time Backup Extractor Alpha"
$root = [IO.Path]::GetFullPath($PSScriptRoot)
$manifestPath = Join-Path $PSScriptRoot "windows-release-manifest.json"
$manifestItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
if ($manifestItem.PSIsContainer -or
    ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    $manifestItem.Length -le 0 -or $manifestItem.Length -gt 1MB) {
    throw "The Windows alpha release manifest was unavailable."
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$thumbprint = [string]$manifest.signing.certificate_thumbprint
if ($manifest.schema -cne "tvtime-windows-alpha-release-v1" -or
    $manifest.release.package_identity -cne $expectedIdentity -or
    $manifest.signing.kind -cne "ephemeral-self-signed-alpha" -or
    $manifest.signing.private_key_included -ne $false -or
    $thumbprint -notmatch '^[0-9A-F]{40}$') {
    throw "The Windows alpha release manifest had an unsupported identity."
}
$helperRecord = $manifest.artifacts.trust_helper
if ($null -eq $helperRecord -or
    $helperRecord.name -isnot [string] -or
    $helperRecord.name -notmatch '^[A-Za-z0-9][A-Za-z0-9._ -]{0,159}$' -or
    $helperRecord.sha256 -isnot [string] -or
    $helperRecord.sha256 -notmatch '^[0-9a-f]{64}$' -or
    ($helperRecord.size -isnot [long] -and $helperRecord.size -isnot [int]) -or
    [long]$helperRecord.size -le 0 -or [long]$helperRecord.size -gt 1MB) {
    throw "The Windows alpha trust helper binding was invalid."
}
$helperPath = [IO.Path]::GetFullPath((Join-Path $root $helperRecord.name))
if (-not $helperPath.StartsWith(
    $root + [IO.Path]::DirectorySeparatorChar,
    [StringComparison]::OrdinalIgnoreCase
)) {
    throw "The Windows alpha trust helper escaped the downloaded bundle."
}
$helperItem = Get-Item -LiteralPath $helperPath -Force -ErrorAction Stop
if ($helperItem.PSIsContainer -or
    ($helperItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    $helperItem.Length -ne [long]$helperRecord.size -or
    (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $helperRecord.sha256) {
    throw "The Windows alpha trust helper did not match its release manifest."
}
$helperPin = [IO.File]::Open(
    $helperPath,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::None
)
try {
    if ($helperPin.Length -ne [long]$helperRecord.size) {
        throw "The pinned Windows alpha trust helper changed size."
    }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $helperDigest = [BitConverter]::ToString(
            $hasher.ComputeHash($helperPin)
        ).Replace("-", "").ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
    if ($helperDigest -cne $helperRecord.sha256) {
        throw "The pinned Windows alpha trust helper changed after verification."
    }
    $helperPin.Position = 0
} catch {
    $helperPin.Dispose()
    throw
}

if (-not $ConfirmRemoval) {
    if ($NonInteractive) {
        throw "Removal requires explicit confirmation."
    }
    Write-Host "Removing the app can delete reports kept in its private app storage."
    Write-Host "Copy any reports you want to keep before continuing."
    $confirmation = Read-Host "Type REMOVE to uninstall the alpha and remove its certificate"
    if ($confirmation -cne "REMOVE") {
        throw "Windows alpha removal was cancelled."
    }
}

$packages = @(Get-AppxPackage -Name $expectedIdentity -ErrorAction Stop)
$removedPackageFullName = ""
if ($packages.Count -gt 1) {
    throw "Windows returned an ambiguous alpha package registration."
}
if ($packages.Count -eq 1) {
    if ($packages[0].Publisher -cne $expectedSubject) {
        throw "The installed alpha package publisher did not match the release."
    }
    $removedPackageFullName = [string]$packages[0].PackageFullName
    if ($removedPackageFullName -cnotmatch '^[A-Za-z0-9._-]{1,255}$') {
        throw "The installed alpha package full name was invalid."
    }
    Remove-AppxPackage -Package $packages[0].PackageFullName -Confirm:$false
    if (@(Get-AppxPackage -Name $expectedIdentity -ErrorAction Stop).Count -ne 0) {
        throw "The Windows alpha package remained installed after removal."
    }
}

$matches = @(Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object {
    $_.Thumbprint -ceq $thumbprint -and
        $_.Subject -ceq $expectedSubject -and
        $_.Issuer -ceq $expectedSubject
})
$certificateRetainedForOtherUsers = $false
if ($matches.Count -gt 1) {
    throw "Windows returned an ambiguous alpha certificate."
}
if ($matches.Count -eq 1) {
    $certificateBytes = [Convert]::ToBase64String($matches[0].RawData)
    $helperPin.Position = 0
    $reader = [IO.StreamReader]::new(
        $helperPin,
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
    $elevatedCommand = $helperSource + "`n" + @"
`$result = Set-PrivateWindowsCertificateTrust -Operation "Remove" -Thumbprint "$thumbprint" -RawCertificateBase64 "$certificateBytes" -PackageFullName "$removedPackageFullName"
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
    if ($process.ExitCode -eq 11) {
        $certificateRetainedForOtherUsers = $true
    } elseif ($process.ExitCode -ne 0) {
        throw "Windows could not remove the exact alpha signing certificate (safe code $($process.ExitCode))."
    }
}

$helperPin.Dispose()

if ($certificateRetainedForOtherUsers) {
    Write-Output "TV Time Backup Extractor Windows alpha was removed. Its certificate remains because another Windows user still has the same release package installed."
} else {
    Write-Output "TV Time Backup Extractor Windows alpha and its certificate were removed."
}
