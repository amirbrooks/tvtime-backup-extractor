[CmdletBinding()]
param([string]$Package = "")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$installed = @(Get-AppxPackage -Name "AmirBrooks.TVTimeBackupExtractor.Private" -ErrorAction Stop)
if ($installed.Count -ne 0) {
    throw "The private package is already installed. Review retained private output before any manual uninstall or versioned update; this installer never removes app data."
}
if (-not $Package) { $Package = & (Join-Path $PSScriptRoot "build_windows_app.ps1") }
$Package = (Resolve-Path $Package).Path
if (-not $Package.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Only a locally built private package beneath this repository may be installed."
}
$subject = "CN=TV Time Backup Extractor Private"
$certificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    $_.Subject -eq $subject -and $_.NotAfter -gt (Get-Date).AddDays(30) -and $_.HasPrivateKey
} | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $certificate) {
    $certificate = New-SelfSignedCertificate -Type Custom -Subject $subject `
        -KeyUsage DigitalSignature -FriendlyName "TV Time Recovery private local install" `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(2) `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
}
$signTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Filter signtool.exe -File -Recurse |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signTool) { throw "The Windows SDK signing tool was not found." }
& $signTool.FullName sign /fd SHA256 /sha1 $certificate.Thumbprint /s My $Package
if ($LASTEXITCODE -ne 0) { throw "The private MSIX could not be signed." }
$publicCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificate.RawData)
$trustedStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPeople", "CurrentUser")
$trustedCertificateAdded = $false
try {
    $trustedStore.Open("ReadWrite")
    $existingTrusted = $trustedStore.Certificates | Where-Object { $_.Thumbprint -eq $publicCertificate.Thumbprint }
    if (-not $existingTrusted) {
        $trustedStore.Add($publicCertificate)
        $trustedCertificateAdded = $true
    }
} finally {
    $trustedStore.Close()
}
$installationCompleted = $false
try {
    & $signTool.FullName verify /pa /v $Package
    if ($LASTEXITCODE -ne 0) { throw "The private MSIX signature could not be verified." }
    $packageSignature = Get-AuthenticodeSignature -FilePath $Package
    if ($packageSignature.Status -ne "Valid" -or
        $packageSignature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) {
        throw "The private MSIX was not signed by the exact reviewed private certificate."
    }
    Add-AppxPackage -Path $Package -ForceApplicationShutdown
    $installationCompleted = $true
} finally {
    if ($trustedCertificateAdded -and -not $installationCompleted) {
        $trustedStore.Open("ReadWrite")
        try {
            $trustedStore.Remove($publicCertificate)
        } finally {
            $trustedStore.Close()
        }
    }
}
Write-Output "Private per-user installation completed. No package was uploaded or published."
