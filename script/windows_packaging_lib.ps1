Set-StrictMode -Version Latest

if ($null -eq ("TVTimeWindowsPackaging.DirectoryCapabilities" -as [Type])) {
    $capabilitySources = @(
        (Join-Path $PSScriptRoot "WindowsPackagingNative.cs"),
        (Join-Path $PSScriptRoot "WindowsPackagingNativeOperations.cs"),
        (Join-Path $PSScriptRoot "WindowsPackagingFile.cs"),
        (Join-Path $PSScriptRoot "WindowsPackagingTree.cs"),
        (Join-Path $PSScriptRoot "WindowsPackagingCapabilities.cs")
    )
    try {
        Add-Type -LiteralPath $capabilitySources | Out-Null
    } finally {
        Remove-Variable capabilitySources -ErrorAction SilentlyContinue
    }
}

function Assert-ContainedOrdinaryDirectoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TrustedRoot,
        [Parameter(Mandatory = $true)][string]$Candidate,
        [switch]$AllowMissingCandidate
    )

    $separators = [char[]]@(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $rootPath = [IO.Path]::GetFullPath($TrustedRoot).TrimEnd($separators)
    $candidatePath = [IO.Path]::GetFullPath($Candidate).TrimEnd($separators)
    $prefix = $rootPath + [IO.Path]::DirectorySeparatorChar
    if (-not $candidatePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "A Windows packaging path escaped its trusted build root."
    }

    $rootItem = Get-Item -LiteralPath $rootPath -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "The trusted Windows packaging root was not an ordinary directory."
    }

    $relative = $candidatePath.Substring($prefix.Length)
    $current = $rootPath
    $missing = $false
    foreach ($component in $relative.Split($separators, [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = Join-Path $current $component
        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            $missing = $true
            continue
        }
        if ($missing -or -not $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "A Windows packaging path contained a link, junction, or unsafe component."
        }
    }
    if ($missing -and -not $AllowMissingCandidate) {
        throw "A required Windows packaging directory was unavailable."
    }
    Write-Output $candidatePath
}

function Assert-DirectContainedChild {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TrustedRoot,
        [Parameter(Mandatory = $true)][string]$Candidate
    )

    $separators = [char[]]@(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $rootPath = [IO.Path]::GetFullPath($TrustedRoot).TrimEnd($separators)
    $candidatePath = Assert-ContainedOrdinaryDirectoryPath `
        -TrustedRoot $rootPath -Candidate $Candidate -AllowMissingCandidate
    if (-not [String]::Equals(
        [IO.Path]::GetDirectoryName($candidatePath),
        $rootPath,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "A new Windows packaging directory was not a direct child of its trusted root."
    }
    Write-Output $candidatePath
}

function New-ContainedOrdinaryDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TrustedRoot,
        [Parameter(Mandatory = $true)][string]$Candidate,
        [object]$TrustedRootOwnership = $null
    )

    $candidatePath = Assert-DirectContainedChild `
        -TrustedRoot $TrustedRoot -Candidate $Candidate
    $rootPath = [IO.Path]::GetDirectoryName($candidatePath)
    if ($null -ne $TrustedRootOwnership) {
        $heldRootPath = Assert-ContainedOrdinaryDirectoryOwnership `
            -OwnershipToken $TrustedRootOwnership
        if (-not [String]::Equals(
            $heldRootPath,
            $rootPath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "The Windows packaging creation root capability did not match its path."
        }
        $heldRoot = Get-OwnershipNativeCapability -OwnershipToken $TrustedRootOwnership
        $capability = [TVTimeWindowsPackaging.DirectoryCapabilities]::CreateChild(
            $heldRoot.Handle,
            [IO.Path]::GetFileName($candidatePath)
        )
    } else {
        $capability = [TVTimeWindowsPackaging.DirectoryCapabilities]::CreateChild(
            $rootPath,
            [IO.Path]::GetFileName($candidatePath)
        )
    }
    [pscustomobject]@{
        TrustedRoot = $rootPath
        Candidate = $candidatePath
        Identity = $capability.Identity
        Capability = $capability
        Snapshot = $null
        Manifest = $null
    }
}

function New-ContainedOrdinaryTreeSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TrustedRoot,
        [Parameter(Mandatory = $true)][string]$Candidate
    )

    $candidatePath = Assert-ContainedOrdinaryDirectoryPath `
        -TrustedRoot $TrustedRoot -Candidate $Candidate
    $snapshot = [TVTimeWindowsPackaging.DirectoryCapabilities]::LockTree($candidatePath)
    [pscustomobject]@{
        TrustedRoot = [IO.Path]::GetFullPath($TrustedRoot)
        Candidate = $candidatePath
        Identity = $snapshot.Identity
        Capability = $null
        Snapshot = $snapshot
        Manifest = $snapshot.Manifest
    }
}

function Convert-ContainedOrdinaryDirectoryToTreeSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$OwnershipToken)

    $candidatePath = Assert-ContainedOrdinaryDirectoryOwnership `
        -OwnershipToken $OwnershipToken
    if ($null -ne $OwnershipToken.Snapshot -or $null -eq $OwnershipToken.Capability) {
        throw "A Windows packaging directory could not be frozen twice."
    }
    $snapshot = [TVTimeWindowsPackaging.DirectoryCapabilities]::FreezeTree(
        $OwnershipToken.Capability,
        $candidatePath
    )
    $OwnershipToken.Capability = $null
    $OwnershipToken.Snapshot = $snapshot
    $OwnershipToken.Identity = $snapshot.Identity
    $OwnershipToken.Manifest = $snapshot.Manifest
    Write-Output $OwnershipToken
}

function Get-OwnershipNativeCapability {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$OwnershipToken)

    if ($null -ne $OwnershipToken.Snapshot) { return $OwnershipToken.Snapshot }
    if ($null -ne $OwnershipToken.Capability) { return $OwnershipToken.Capability }
    throw "A Windows packaging ownership token had no retained capability."
}

function Assert-ContainedOrdinaryDirectoryOwnership {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$OwnershipToken)

    $candidatePath = Assert-ContainedOrdinaryDirectoryPath `
        -TrustedRoot $OwnershipToken.TrustedRoot -Candidate $OwnershipToken.Candidate
    $native = Get-OwnershipNativeCapability -OwnershipToken $OwnershipToken
    if ([TVTimeWindowsPackaging.DirectoryCapabilities]::ReadHandleIdentity($native.Handle) -ne
        $OwnershipToken.Identity -or
        [TVTimeWindowsPackaging.DirectoryCapabilities]::ReadPathIdentity($candidatePath) -ne
        $OwnershipToken.Identity) {
        throw "An owned Windows packaging directory was replaced."
    }
    Write-Output $candidatePath
}

function Assert-ContainedOrdinaryTreeSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$OwnershipToken)

    if ($null -eq $OwnershipToken.Snapshot -or
        $null -ne $OwnershipToken.Capability -or
        $OwnershipToken.Manifest -cne $OwnershipToken.Snapshot.Manifest) {
        throw "A Windows packaging tree token did not retain its immutable manifest."
    }
    $candidatePath = Assert-ContainedOrdinaryDirectoryOwnership `
        -OwnershipToken $OwnershipToken
    [TVTimeWindowsPackaging.DirectoryCapabilities]::RevalidateTree(
        $OwnershipToken.Snapshot,
        $candidatePath
    )
    Write-Output $candidatePath
}

function Release-ContainedOrdinaryDirectoryOwnership {
    [CmdletBinding()]
    param([object]$OwnershipToken)

    if ($null -eq $OwnershipToken) { return }
    if ($null -ne $OwnershipToken.Snapshot) {
        $OwnershipToken.Snapshot.Dispose()
        $OwnershipToken.Snapshot = $null
    }
    if ($null -ne $OwnershipToken.Capability) {
        $OwnershipToken.Capability.Dispose()
        $OwnershipToken.Capability = $null
    }
}

function Remove-ContainedOrdinaryTree {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$OwnershipToken)

    $operationError = $null
    try {
        $item = Get-Item -LiteralPath $OwnershipToken.Candidate -Force -ErrorAction SilentlyContinue
        if ($null -eq $item) { return }
        $candidatePath = Assert-ContainedOrdinaryDirectoryOwnership `
            -OwnershipToken $OwnershipToken
        if ($null -ne $OwnershipToken.Snapshot) {
            try {
                Assert-ContainedOrdinaryTreeSnapshot `
                    -OwnershipToken $OwnershipToken | Out-Null
            } catch {
                $operationError = $_
            }
            try {
                [TVTimeWindowsPackaging.DirectoryCapabilities]::DeleteTree(
                    $candidatePath,
                    $OwnershipToken.Snapshot
                )
            } catch {
                if ($null -eq $operationError) { $operationError = $_ }
            }
        } else {
            try {
                [TVTimeWindowsPackaging.DirectoryCapabilities]::DeleteTree(
                    $candidatePath,
                    $OwnershipToken.Capability
                )
            } catch {
                $operationError = $_
            }
        }
    } finally {
        Release-ContainedOrdinaryDirectoryOwnership -OwnershipToken $OwnershipToken
    }
    if ($null -ne $operationError) { throw $operationError }
}

function Move-ContainedOrdinaryDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$OwnershipToken,
        [Parameter(Mandatory = $true)][string]$DestinationTrustedRoot,
        [Parameter(Mandatory = $true)][string]$Destination,
        [object]$DestinationRootOwnership = $null
    )

    $sourcePath = [IO.Path]::GetFullPath($OwnershipToken.Candidate)
    $destinationPath = $null
    $movedDestination = $null
    try {
    Assert-ContainedOrdinaryDirectoryOwnership -OwnershipToken $OwnershipToken | Out-Null
    $destinationPath = Assert-DirectContainedChild `
        -TrustedRoot $DestinationTrustedRoot -Candidate $Destination
    if ($null -ne (Get-Item -LiteralPath $destinationPath -Force -ErrorAction SilentlyContinue)) {
        throw "A Windows packaging promotion destination already existed."
    }
    if ($null -ne $DestinationRootOwnership) {
            $destinationRootPath = Assert-ContainedOrdinaryDirectoryOwnership `
                -OwnershipToken $DestinationRootOwnership
            if (-not [String]::Equals(
                $destinationRootPath,
                [IO.Path]::GetFullPath($DestinationTrustedRoot),
                [StringComparison]::OrdinalIgnoreCase
            )) {
                throw "The Windows packaging promotion root capability did not match its path."
            }
            $destinationRootNative = Get-OwnershipNativeCapability `
                -OwnershipToken $DestinationRootOwnership
            if ($null -ne $OwnershipToken.Snapshot) {
                [TVTimeWindowsPackaging.DirectoryCapabilities]::Rename(
                    $OwnershipToken.Snapshot,
                    $destinationRootNative.Handle,
                    $destinationRootPath,
                    [IO.Path]::GetFileName($destinationPath)
                )
            } else {
                $movedDestination = [TVTimeWindowsPackaging.DirectoryCapabilities]::Rename(
                    $OwnershipToken.Capability,
                    $destinationRootNative.Handle,
                    $destinationRootPath,
                    [IO.Path]::GetFileName($destinationPath)
                )
                $OwnershipToken.TrustedRoot = [IO.Path]::GetFullPath($DestinationTrustedRoot)
                $OwnershipToken.Candidate = [IO.Path]::GetFullPath($movedDestination)
            }
    } elseif ($null -ne $OwnershipToken.Snapshot) {
            [TVTimeWindowsPackaging.DirectoryCapabilities]::Rename(
                $OwnershipToken.Snapshot,
                [IO.Path]::GetFullPath($DestinationTrustedRoot),
                [IO.Path]::GetFileName($destinationPath)
            )
    } else {
            $movedDestination = [TVTimeWindowsPackaging.DirectoryCapabilities]::Rename(
                $OwnershipToken.Capability,
                [IO.Path]::GetFullPath($DestinationTrustedRoot),
                [IO.Path]::GetFileName($destinationPath)
            )
            $OwnershipToken.TrustedRoot = [IO.Path]::GetFullPath($DestinationTrustedRoot)
            $OwnershipToken.Candidate = [IO.Path]::GetFullPath($movedDestination)
    }
    if ($null -ne $movedDestination -and -not [String]::Equals(
        [IO.Path]::GetFullPath($movedDestination),
        $destinationPath,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "The native Windows packaging move returned an unexpected destination."
    }
    $OwnershipToken.TrustedRoot = [IO.Path]::GetFullPath($DestinationTrustedRoot)
    $OwnershipToken.Candidate = $destinationPath
    Assert-ContainedOrdinaryDirectoryOwnership -OwnershipToken $OwnershipToken | Out-Null
    Write-Output $OwnershipToken
    } catch {
        $moveError = $_
        if ($null -ne $OwnershipToken.Snapshot -and
            $null -ne $destinationPath -and
            -not [String]::Equals(
                $sourcePath,
                $destinationPath,
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            [String]::Equals(
                [IO.Path]::GetFullPath($OwnershipToken.Snapshot.Path),
                $destinationPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            # Rename already completed and the retained root now names the
            # destination. Preserve the token so an outer cleanup can delete the
            # exact moved tree even when post-rename verification or relocking
            # detected a failure.
            $OwnershipToken.TrustedRoot = [IO.Path]::GetFullPath($DestinationTrustedRoot)
            $OwnershipToken.Candidate = $destinationPath
            throw $moveError
        }
        # The caller still owns the source when rename did not occur. Preserve
        # that exact capability so its outer failure cleanup can remove the
        # staging tree instead of leaking it.
        throw $moveError
    }
}

function Remove-ContainedOrdinaryTrees {
    [CmdletBinding()]
    param(
        [object[]]$OwnershipTokens = @(),
        [object]$PrimaryError = $null
    )

    $cleanupError = $null
    foreach ($ownershipToken in $OwnershipTokens) {
        if ($null -eq $ownershipToken) { continue }
        try {
            Remove-ContainedOrdinaryTree -OwnershipToken $ownershipToken
        } catch {
            if ($null -eq $cleanupError) { $cleanupError = $_ }
        }
    }
    if ($null -ne $PrimaryError) { throw $PrimaryError }
    if ($null -ne $cleanupError) { throw $cleanupError }
}
