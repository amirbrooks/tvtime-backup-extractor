$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "windows_packaging_lib.ps1")
. (Join-Path $PSScriptRoot "windows_msix_integrity.ps1")

$base = Join-Path $env:RUNNER_TEMP ("tvtime-msix-test-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $base -ErrorAction Stop | Out-Null
$testRootOwnership = $null
$outsideOwnership = $null
$bodyError = $null
try {
    $testRoot = Join-Path $base "root"
    $outside = Join-Path $base "outside"
    $testRootOwnership = New-ContainedOrdinaryDirectory `
        -TrustedRoot $base -Candidate $testRoot
    $outsideOwnership = New-ContainedOrdinaryDirectory `
        -TrustedRoot $base -Candidate $outside

    $missingPackage = Join-Path $testRoot "missing-package.msix"
    $missingPackageRejected = $false
    try {
        $missingPin = Open-PrivateMsixIdentityPin `
            -OutputRootOwnership $testRootOwnership -Package $missingPackage
        $missingPin.Dispose()
    } catch {
        $missingPackageRejected = $true
    }
    if (-not $missingPackageRejected -or Test-Path -LiteralPath $missingPackage) {
        throw "A missing MSIX path was created while acquiring a read-only pin."
    }

    $missingDirectory = Join-Path $testRoot "missing-parent"
    $missingNestedPackage = Join-Path $missingDirectory "missing-package.msix"
    $missingDirectoryRejected = $false
    try {
        $missingNestedPin = Open-PrivateMsixIdentityPin `
            -OutputRootOwnership $testRootOwnership -Package $missingNestedPackage
        $missingNestedPin.Dispose()
    } catch {
        $missingDirectoryRejected = $true
    }
    if (-not $missingDirectoryRejected -or Test-Path -LiteralPath $missingDirectory) {
        throw "A missing MSIX ancestor was created while acquiring a read-only pin."
    }

    Add-Type -AssemblyName System.IO.Compression
    $syntheticMsix = Join-Path $testRoot "synthetic-package.msix"
    $msixStream = [IO.File]::Open(
        $syntheticMsix,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $msixStream,
            [IO.Compression.ZipArchiveMode]::Create,
            $true
        )
        try {
            $entry = $archive.CreateEntry("AppxBlockMap.xml")
            $writer = [IO.StreamWriter]::new($entry.Open(), [Text.Encoding]::UTF8)
            try {
                $writer.Write("<BlockMap synthetic=`"true`" />")
            } finally {
                $writer.Dispose()
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $msixStream.Dispose()
    }

    $identityPin = Open-PrivateMsixIdentityPin `
        -OutputRootOwnership $testRootOwnership -Package $syntheticMsix
    try {
        $packageDigest = Get-PrivateMsixSha256 -PackageStream $identityPin.Stream
        $digest = Get-PrivateMsixBlockMapDigest -PackageStream $identityPin.Stream
        if ($packageDigest -notmatch "^[0-9a-f]{64}$") {
            throw "The synthetic MSIX package digest was invalid."
        }
        if ($digest -notmatch "^[0-9a-f]{64}$") {
            throw "The synthetic MSIX block-map digest was invalid."
        }
        $overlappingRead = Open-PrivateMsixStrictReadPin `
            -OutputRootOwnership $testRootOwnership `
            -Package $syntheticMsix `
            -ExpectedIdentity $identityPin.Identity
        if ($overlappingRead.Identity -cne $identityPin.Identity) {
            throw "The overlapping MSIX read pin changed FileId."
        }
        $overlappingRead.Dispose()
        $wrongIdentityRejected = $false
        try {
            $wrongIdentityPin = Open-PrivateMsixStrictReadPin `
                -OutputRootOwnership $testRootOwnership `
                -Package $syntheticMsix `
                -ExpectedIdentity ([string]::new('0', 48))
            $wrongIdentityPin.Dispose()
        } catch {
            $wrongIdentityRejected = $true
        }
        if (-not $wrongIdentityRejected) {
            throw "The strict MSIX read pin accepted a different FileId."
        }

        $identityDeleteRejected = $false
        try { [IO.File]::Delete($syntheticMsix) } catch { $identityDeleteRejected = $true }
        $identityReplacement = Join-Path $testRoot "identity-replacement.msix"
        [IO.File]::WriteAllBytes($identityReplacement, [byte[]](1, 2, 3))
        $identityReplaceRejected = $false
        try {
            [IO.File]::Replace($identityReplacement, $syntheticMsix, $null)
        } catch {
            $identityReplaceRejected = $true
        }
        if (-not $identityDeleteRejected -or -not $identityReplaceRejected -or
            -not (Test-Path -LiteralPath $syntheticMsix -PathType Leaf)) {
            throw "The MSIX identity pin did not deny deletion and replacement."
        }
        Remove-Item -LiteralPath $identityReplacement -Force
    } finally {
        $identityPin.Dispose()
    }

    $strictIdentityPin = Open-PrivateMsixIdentityPin `
        -OutputRootOwnership $testRootOwnership -Package $syntheticMsix
    $strictPin = Open-PrivateMsixStrictReadPin `
        -OutputRootOwnership $testRootOwnership `
        -Package $syntheticMsix `
        -ExpectedIdentity $strictIdentityPin.Identity
    $strictIdentityPin.Dispose()
    try {
        $strictWriteRejected = $false
        try {
            $writer = [IO.File]::Open(
                $syntheticMsix,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Write,
                ([IO.FileShare]::Read -bor [IO.FileShare]::Write -bor [IO.FileShare]::Delete)
            )
            $writer.Dispose()
        } catch {
            $strictWriteRejected = $true
        }
        $strictDeleteRejected = $false
        try { [IO.File]::Delete($syntheticMsix) } catch { $strictDeleteRejected = $true }
        $strictReplacement = Join-Path $testRoot "strict-replacement.msix"
        [IO.File]::WriteAllBytes($strictReplacement, [byte[]](4, 5, 6))
        $strictReplaceRejected = $false
        try {
            [IO.File]::Replace($strictReplacement, $syntheticMsix, $null)
        } catch {
            $strictReplaceRejected = $true
        }
        if (-not $strictWriteRejected -or -not $strictDeleteRejected -or
            -not $strictReplaceRejected -or
            -not (Test-Path -LiteralPath $syntheticMsix -PathType Leaf)) {
            throw "The strict MSIX read pin did not deny write, deletion, and replacement."
        }
        Remove-Item -LiteralPath $strictReplacement -Force
    } finally {
        $strictPin.Dispose()
    }

    $linkedPackage = Join-Path $outside "synthetic-linked.msix"
    Copy-Item -LiteralPath $syntheticMsix -Destination $linkedPackage
    $packageJunction = Join-Path $testRoot "synthetic-package-junction"
    & cmd.exe /d /c "mklink /J `"$packageJunction`" `"$outside`"" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "The synthetic package junction could not be created."
    }
    $junctionPackageRejected = $false
    try {
        $junctionPin = Open-PrivateMsixIdentityPin `
            -OutputRootOwnership $testRootOwnership `
            -Package (Join-Path $packageJunction "synthetic-linked.msix")
        $junctionPin.Dispose()
    } catch {
        $junctionPackageRejected = $true
    }
    if (-not $junctionPackageRejected) {
        throw "Handle-relative MSIX acquisition followed a junction."
    }
    [IO.Directory]::Delete($packageJunction)
    Remove-Item -LiteralPath $linkedPackage -Force
    Remove-Item -LiteralPath $syntheticMsix -Force
} catch {
    $bodyError = $_
} finally {
    Remove-ContainedOrdinaryTrees `
        -OwnershipTokens @($testRootOwnership, $outsideOwnership) `
        -PrimaryError $bodyError
    [IO.Directory]::Delete($base)
}

Write-Output "Windows MSIX capability and digest checks passed."
