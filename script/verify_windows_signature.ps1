[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Package,
    [Parameter(Mandatory = $true)][string]$Certificate,
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[A-F0-9]{40}$")]
    [string]$ExpectedThumbprint
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$expectedSubject = "CN=TV Time Backup Extractor Alpha"
$codeSigningOid = "1.3.6.1.5.5.7.3.3"
$certificateAdded = $false
$bodyError = $null
$publicCertificate = $null
$trustStore = $null

function Assert-OrdinaryBoundedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "A Windows signature input had an unsafe file shape."
    }
}

try {
    $packagePath = [IO.Path]::GetFullPath($Package)
    $certificatePath = [IO.Path]::GetFullPath($Certificate)
    Assert-OrdinaryBoundedFile -Path $packagePath -MaximumBytes 1GB
    Assert-OrdinaryBoundedFile -Path $certificatePath -MaximumBytes 64KB

    $publicCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        [IO.File]::ReadAllBytes($certificatePath)
    )
    $ekuExtensions = @(
        $publicCertificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
    )
    $keyUsageExtensions = @(
        $publicCertificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.15" }
    )
    $basicConstraintsExtensions = @(
        $publicCertificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
    )
    if ($publicCertificate.Thumbprint -cne $ExpectedThumbprint -or
        $publicCertificate.Subject -cne $expectedSubject -or
        $publicCertificate.Issuer -cne $expectedSubject -or
        $publicCertificate.HasPrivateKey -or
        $publicCertificate.NotBefore -gt (Get-Date) -or
        $publicCertificate.NotAfter -le (Get-Date).AddDays(7) -or
        $ekuExtensions.Count -ne 1 -or
        $ekuExtensions[0].EnhancedKeyUsages.Count -ne 1 -or
        $ekuExtensions[0].EnhancedKeyUsages[0].Value -ne $codeSigningOid -or
        $keyUsageExtensions.Count -ne 1 -or
        $keyUsageExtensions[0].KeyUsages -ne
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -or
        $basicConstraintsExtensions.Count -ne 1 -or
        $basicConstraintsExtensions[0].CertificateAuthority) {
        throw "The Windows alpha certificate did not match the reviewed signing profile."
    }

    $trustStore = [Security.Cryptography.X509Certificates.X509Store]::new(
        "TrustedPeople",
        "LocalMachine"
    )
    $trustStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $matches = @(
        $trustStore.Certificates | Where-Object { $_.Thumbprint -ceq $ExpectedThumbprint }
    )
    if ($matches.Count -gt 1 -or
        ($matches.Count -eq 1 -and
            [Convert]::ToBase64String($matches[0].RawData) -cne
                [Convert]::ToBase64String($publicCertificate.RawData))) {
        throw "The machine trust store contained ambiguous alpha certificate state."
    }
    if ($matches.Count -eq 0) {
        $trustStore.Add($publicCertificate)
        $certificateAdded = $true
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $packagePath
    if ($signature.Status -ne "Valid" -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -cne $ExpectedThumbprint) {
        throw "The Windows MSIX signature did not match its bundled alpha certificate."
    }
} catch {
    $bodyError = $_
} finally {
    if ($certificateAdded -and $null -ne $trustStore -and $null -ne $publicCertificate) {
        try {
            $addedMatches = @(
                $trustStore.Certificates | Where-Object {
                    $_.Thumbprint -ceq $ExpectedThumbprint -and
                    [Convert]::ToBase64String($_.RawData) -ceq
                        [Convert]::ToBase64String($publicCertificate.RawData)
                }
            )
            foreach ($addedMatch in $addedMatches) { $trustStore.Remove($addedMatch) }
            if (@(
                $trustStore.Certificates | Where-Object {
                    $_.Thumbprint -ceq $ExpectedThumbprint
                }
            ).Count -ne 0) {
                throw "Temporary machine alpha trust remained after verification."
            }
        } catch {
            if ($null -eq $bodyError) {
                $bodyError = $_
            } else {
                $bodyError = [InvalidOperationException]::new(
                    "Signature verification failed and temporary trust cleanup also failed.",
                    $bodyError.Exception
                )
            }
        }
    }
    if ($null -ne $trustStore) { $trustStore.Dispose() }
    if ($null -ne $publicCertificate) { $publicCertificate.Dispose() }
}

if ($null -ne $bodyError) { throw $bodyError }
