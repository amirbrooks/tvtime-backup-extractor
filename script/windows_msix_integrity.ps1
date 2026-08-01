Set-StrictMode -Version Latest

$script:MaximumPrivateMsixBytes = 4GB
$script:MaximumBlockMapBytes = 64MB
$script:MaximumMsixEntries = 200000

function Resolve-PrivateMsixCapabilityPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$OutputRootOwnership,
        [Parameter(Mandatory = $true)][string]$Package
    )

    $rootPath = Assert-ContainedOrdinaryDirectoryOwnership `
        -OwnershipToken $OutputRootOwnership
    $packagePath = [IO.Path]::GetFullPath($Package)
    $separators = [char[]]@(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $prefix = $rootPath.TrimEnd($separators) + [IO.Path]::DirectorySeparatorChar
    if (-not $packagePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not [String]::Equals(
            [IO.Path]::GetExtension($packagePath),
            ".msix",
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "The private Windows package escaped its retained output root."
    }
    $relativePath = $packagePath.Substring($prefix.Length)
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        throw "The private Windows package path was unavailable."
    }
    $nativeRoot = Get-OwnershipNativeCapability -OwnershipToken $OutputRootOwnership
    [pscustomobject]@{
        FullPath = $packagePath
        RelativePath = $relativePath
        RootHandle = $nativeRoot.Handle
    }
}

function Open-PrivateMsixIdentityPin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$OutputRootOwnership,
        [Parameter(Mandatory = $true)][string]$Package
    )

    $binding = Resolve-PrivateMsixCapabilityPath `
        -OutputRootOwnership $OutputRootOwnership -Package $Package
    # One handle-relative no-follow open performs initial acquisition and
    # validation. Signing needs write sharing, while omitted delete sharing pins
    # the exact FileId and every traversed directory against replacement.
    Write-Output ([TVTimeWindowsPackaging.FileCapabilities]::OpenIdentityPin(
        $binding.RootHandle,
        $binding.RelativePath
    ))
}

function Open-PrivateMsixStrictReadPin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$OutputRootOwnership,
        [Parameter(Mandatory = $true)][string]$Package,
        [Parameter(Mandatory = $true)][string]$ExpectedIdentity
    )

    $binding = Resolve-PrivateMsixCapabilityPath `
        -OutputRootOwnership $OutputRootOwnership -Package $Package
    # Readers such as SignTool verification and Add-AppxPackage can coexist;
    # writers, deletion, replacement, and a different FileId cannot.
    Write-Output ([TVTimeWindowsPackaging.FileCapabilities]::OpenStrictReadPin(
        $binding.RootHandle,
        $binding.RelativePath,
        $ExpectedIdentity
    ))
}

function Get-PrivateMsixSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][IO.Stream]$PackageStream)

    if (-not $PackageStream.CanRead -or -not $PackageStream.CanSeek -or
        $PackageStream.Length -le 0 -or
        $PackageStream.Length -gt $script:MaximumPrivateMsixBytes) {
        throw "The private Windows package stream was unavailable or unbounded."
    }
    $position = $PackageStream.Position
    $algorithm = $null
    try {
        $PackageStream.Position = 0
        $algorithm = [Security.Cryptography.SHA256]::Create()
        $digest = $algorithm.ComputeHash($PackageStream)
        Write-Output ([BitConverter]::ToString($digest).Replace("-", "").ToLowerInvariant())
    } finally {
        if ($null -ne $algorithm) { $algorithm.Dispose() }
        $PackageStream.Position = $position
    }
}

function Get-PrivateMsixBlockMapDigest {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][IO.Stream]$PackageStream)

    if (-not $PackageStream.CanRead -or -not $PackageStream.CanSeek -or
        $PackageStream.Length -le 0 -or
        $PackageStream.Length -gt $script:MaximumPrivateMsixBytes) {
        throw "The private Windows package stream was unavailable or unbounded."
    }

    Add-Type -AssemblyName System.IO.Compression
    $position = $PackageStream.Position
    $archive = $null
    $entryStream = $null
    $algorithm = $null
    try {
        $PackageStream.Position = 0
        $archive = [IO.Compression.ZipArchive]::new(
            $PackageStream,
            [IO.Compression.ZipArchiveMode]::Read,
            $true
        )
        $blockMap = $null
        $entryCount = 0
        foreach ($entry in $archive.Entries) {
            $entryCount++
            if ($entryCount -gt $script:MaximumMsixEntries) {
                throw "The private Windows package contained too many entries."
            }
            if ([String]::Equals(
                $entry.FullName,
                "AppxBlockMap.xml",
                [StringComparison]::OrdinalIgnoreCase
            )) {
                if ($null -ne $blockMap) {
                    throw "The private Windows package contained an ambiguous block map."
                }
                $blockMap = $entry
            }
        }
        if ($null -eq $blockMap -or $blockMap.Length -le 0 -or
            $blockMap.Length -gt $script:MaximumBlockMapBytes) {
            throw "The private Windows package did not contain one bounded block map."
        }
        $entryStream = $blockMap.Open()
        $algorithm = [Security.Cryptography.SHA256]::Create()
        $digest = $algorithm.ComputeHash($entryStream)
        Write-Output ([BitConverter]::ToString($digest).Replace("-", "").ToLowerInvariant())
    } catch {
        throw "The private Windows package block map could not be read safely."
    } finally {
        if ($null -ne $algorithm) { $algorithm.Dispose() }
        if ($null -ne $entryStream) { $entryStream.Dispose() }
        if ($null -ne $archive) { $archive.Dispose() }
        $PackageStream.Position = $position
    }
}
