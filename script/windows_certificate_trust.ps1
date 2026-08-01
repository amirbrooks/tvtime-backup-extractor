function Set-PrivateWindowsCertificateTrust {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Add", "Remove")]
        [string]$Operation,

        [Parameter(Mandatory = $true)]
        [ValidatePattern("^[A-F0-9]{40}$")]
        [string]$Thumbprint,

        [Parameter(Mandatory = $true)]
        [ValidatePattern("^[A-Za-z0-9+/]+={0,2}$")]
        [string]$RawCertificateBase64
    )

    $ErrorActionPreference = "Stop"
    Set-StrictMode -Version Latest
    $certificateAdded = $false
    try {
        if ($RawCertificateBase64.Length -gt 4096) {
            throw "The requested private package certificate is too large."
        }
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $currentPrincipal = New-Object `
                Security.Principal.WindowsPrincipal($currentIdentity)
            $isAdministrator = $currentPrincipal.IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator
            )
        } finally {
            $currentIdentity.Dispose()
        }
        if (-not $isAdministrator) { throw "Machine certificate trust requires elevation." }

        $rawCertificate = [Convert]::FromBase64String($RawCertificateBase64)
        $certificate = New-Object `
            System.Security.Cryptography.X509Certificates.X509Certificate2($rawCertificate)
        try {
            $subject = "CN=TV Time Backup Extractor Private"
            $codeSigningOid = "1.3.6.1.5.5.7.3.3"
            $ekuExtensions = @(
                $certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
            )
            $keyUsageExtensions = @(
                $certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.15" }
            )
            $basicConstraintsExtensions = @(
                $certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
            )
            if ($ekuExtensions.Count -ne 1 -or
                $ekuExtensions[0].EnhancedKeyUsages.Count -ne 1 -or
                $ekuExtensions[0].EnhancedKeyUsages[0].Value -ne $codeSigningOid -or
                $keyUsageExtensions.Count -ne 1 -or
                $keyUsageExtensions[0].KeyUsages -ne
                    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -or
                $basicConstraintsExtensions.Count -ne 1 -or
                $basicConstraintsExtensions[0].CertificateAuthority -or
                $certificate.Subject -ne $subject -or
                $certificate.Issuer -ne $subject -or
                $certificate.Thumbprint -cne $Thumbprint -or
                $certificate.NotBefore -gt (Get-Date) -or
                $certificate.NotAfter -le (Get-Date).AddDays(30) -or
                $certificate.HasPrivateKey) {
                throw "The requested private package certificate is not allowed."
            }

            $store = New-Object `
                System.Security.Cryptography.X509Certificates.X509Store(
                    "TrustedPeople",
                    "LocalMachine"
                )
            try {
                $store.Open("ReadWrite")
                $matches = @(
                    $store.Certificates | Where-Object { $_.Thumbprint -ceq $Thumbprint }
                )
                if ($matches.Count -gt 1) {
                    throw "The machine trust store contains ambiguous certificate state."
                }
                if ($matches.Count -eq 1 -and
                    [Convert]::ToBase64String($matches[0].RawData) -cne
                        $RawCertificateBase64) {
                    throw "The machine trust store contains mismatched certificate state."
                }

                if ($Operation -eq "Add") {
                    if ($matches.Count -eq 1) { return 10 }
                    $store.Add($certificate)
                    $certificateAdded = $true
                    $added = @(
                        $store.Certificates | Where-Object {
                            $_.Thumbprint -ceq $Thumbprint -and
                            [Convert]::ToBase64String($_.RawData) -ceq
                                $RawCertificateBase64
                        }
                    )
                    if ($added.Count -ne 1) {
                        throw "The private package certificate was not trusted exactly."
                    }
                    return 0
                }

                if ($matches.Count -eq 1) { $store.Remove($matches[0]) }
                $remaining = @(
                    $store.Certificates | Where-Object { $_.Thumbprint -ceq $Thumbprint }
                )
                if ($remaining.Count -ne 0) {
                    throw "The private package certificate trust was not removed."
                }
                return 0
            } finally {
                $store.Close()
            }
        } finally {
            $certificate.Dispose()
        }
    } catch {
        if ($certificateAdded) {
            try {
                $rollbackStore = New-Object `
                    System.Security.Cryptography.X509Certificates.X509Store(
                        "TrustedPeople",
                        "LocalMachine"
                    )
                try {
                    $rollbackStore.Open("ReadWrite")
                    $rollbackMatches = @(
                        $rollbackStore.Certificates | Where-Object {
                            $_.Thumbprint -ceq $Thumbprint -and
                            [Convert]::ToBase64String($_.RawData) -ceq
                                $RawCertificateBase64
                        }
                    )
                    foreach ($rollbackMatch in $rollbackMatches) {
                        $rollbackStore.Remove($rollbackMatch)
                    }
                    $rollbackRemaining = @(
                        $rollbackStore.Certificates | Where-Object {
                            $_.Thumbprint -ceq $Thumbprint
                        }
                    )
                    if ($rollbackRemaining.Count -ne 0) {
                        throw "The private package certificate trust rollback did not complete."
                    }
                } finally {
                    $rollbackStore.Close()
                }
            } catch {
                return 21
            }
        }
        if ($Operation -eq "Remove") { return 21 }
        return 20
    }
}
