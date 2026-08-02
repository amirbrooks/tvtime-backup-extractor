$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "windows_packaging_lib.ps1")

$base = Join-Path $env:RUNNER_TEMP ("tvtime-packaging-test-" + [Guid]::NewGuid().ToString("N"))
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


    $ordinary = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "ordinary") `
        -TrustedRootOwnership $testRootOwnership
    $ordinaryCapability = $ordinary.Capability
    Set-Content -LiteralPath (Join-Path $ordinary.Candidate "synthetic.txt") `
        -Value "synthetic" -Encoding Ascii -NoNewline
    Remove-ContainedOrdinaryTree -OwnershipToken $ordinary
    if ((Test-Path -LiteralPath $ordinary.Candidate) -or
        -not $ordinaryCapability.Handle.IsClosed) {
        throw "Identity-bound Windows packaging cleanup left an ordinary test tree behind."
    }

    $owned = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "owned") `
        -TrustedRootOwnership $testRootOwnership
    $ownedOriginal = $owned.Candidate
    $staleOwned = [pscustomobject]@{
        TrustedRoot = $owned.TrustedRoot
        Candidate = $owned.Candidate
        Identity = $owned.Identity
        Capability = $owned.Capability
        Snapshot = $null
        Manifest = $null
    }
    $displaced = Move-ContainedOrdinaryDirectory `
        -OwnershipToken $owned `
        -DestinationTrustedRoot $testRoot `
        -Destination (Join-Path $testRoot "displaced") `
        -DestinationRootOwnership $testRootOwnership
    $replacement = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate $ownedOriginal `
        -TrustedRootOwnership $testRootOwnership
    $replacementRejected = $false
    try {
        Remove-ContainedOrdinaryTree -OwnershipToken $staleOwned
    } catch {
        $replacementRejected = $true
    }
    if (-not $replacementRejected -or -not (Test-Path -LiteralPath $replacement.Candidate)) {
        throw "Windows packaging cleanup did not preserve an unowned replacement directory."
    }
    if (-not $owned.Capability.Handle.IsClosed) {
        throw "A rejected stale ownership token left its native handle open."
    }
    $displacedPath = $displaced.Candidate
    Release-ContainedOrdinaryDirectoryOwnership -OwnershipToken $displaced
    $displacedSnapshot = New-ContainedOrdinaryTreeSnapshot `
        -TrustedRoot $testRoot -Candidate $displacedPath
    Remove-ContainedOrdinaryTrees -OwnershipTokens @($replacement, $displacedSnapshot)

    $identityGuard = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "identity-guard") `
        -TrustedRootOwnership $testRootOwnership
    $badIdentityGuard = [pscustomobject]@{
        TrustedRoot = $identityGuard.TrustedRoot
        Candidate = $identityGuard.Candidate
        Identity = [string]::new('0', 48)
        Capability = $identityGuard.Capability
        Snapshot = $null
        Manifest = $null
    }
    $identityRejected = $false
    try {
        Remove-ContainedOrdinaryTree -OwnershipToken $badIdentityGuard
    } catch {
        $identityRejected = $true
    }
    if (-not $identityRejected -or -not (Test-Path -LiteralPath $identityGuard.Candidate)) {
        throw "The native cleanup primitive did not reject a mismatched directory identity."
    }
    if (-not $identityGuard.Capability.Handle.IsClosed) {
        throw "A rejected identity token left its native handle open."
    }
    $identityGuardPath = $identityGuard.Candidate
    Release-ContainedOrdinaryDirectoryOwnership -OwnershipToken $identityGuard
    $identityGuardSnapshot = New-ContainedOrdinaryTreeSnapshot `
        -TrustedRoot $testRoot -Candidate $identityGuardPath
    Remove-ContainedOrdinaryTree -OwnershipToken $identityGuardSnapshot

    $moveFailure = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "move-failure") `
        -TrustedRootOwnership $testRootOwnership
    $moveBlocker = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "move-blocker") `
        -TrustedRootOwnership $testRootOwnership
    $moveFailureCapability = $moveFailure.Capability
    $moveRejected = $false
    try {
        Move-ContainedOrdinaryDirectory `
            -OwnershipToken $moveFailure `
            -DestinationTrustedRoot $testRoot `
            -Destination $moveBlocker.Candidate `
            -DestinationRootOwnership $testRootOwnership | Out-Null
    } catch {
        $moveRejected = $true
    }
    if (-not $moveRejected -or $moveFailureCapability.Handle.IsClosed -or
        -not (Test-Path -LiteralPath $moveFailure.Candidate)) {
        throw "A rejected Windows packaging move did not preserve its source capability."
    }
    Remove-ContainedOrdinaryTrees `
        -OwnershipTokens @($moveFailure, $moveBlocker)
    if ((Test-Path -LiteralPath $moveFailure.Candidate) -or
        -not $moveFailureCapability.Handle.IsClosed) {
        throw "Cleanup after a rejected Windows packaging move left its source behind."
    }

    $freezeConflict = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "freeze-conflict") `
        -TrustedRootOwnership $testRootOwnership
    $freezeConflictFile = Join-Path $freezeConflict.Candidate "synthetic.bin"
    Set-Content -LiteralPath $freezeConflictFile `
        -Value "synthetic-conflict" -Encoding Ascii -NoNewline
    $freezeConflictCapability = $freezeConflict.Capability
    $freezeConflictHandle = $freezeConflictCapability.Handle
    $conflictingWriter = [IO.File]::Open(
        $freezeConflictFile,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Write,
        ([IO.FileShare]::Read -bor [IO.FileShare]::Write)
    )
    $freezeConflictRejected = $false
    try {
        Convert-ContainedOrdinaryDirectoryToTreeSnapshot `
            -OwnershipToken $freezeConflict | Out-Null
    } catch {
        $freezeConflictRejected = $true
    } finally {
        $conflictingWriter.Dispose()
    }
    if (-not $freezeConflictRejected -or
        -not [Object]::ReferenceEquals(
            $freezeConflictHandle,
            $freezeConflict.Capability.Handle
        ) -or $freezeConflictHandle.IsClosed) {
        throw "A failed snapshot lock did not preserve its exact cleanup capability."
    }
    Remove-ContainedOrdinaryTree -OwnershipToken $freezeConflict
    if ((Test-Path -LiteralPath $freezeConflict.Candidate) -or
        -not $freezeConflictHandle.IsClosed) {
        throw "Cleanup after a snapshot sharing conflict left its owned tree behind."
    }

    $nonemptyMoveMutable = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "nonempty-move-source") `
        -TrustedRootOwnership $testRootOwnership
    $nonemptyNested = Join-Path $nonemptyMoveMutable.Candidate "nested"
    [IO.Directory]::CreateDirectory($nonemptyNested) | Out-Null
    Set-Content -LiteralPath (Join-Path $nonemptyMoveMutable.Candidate "root.txt") `
        -Value "synthetic-root" -Encoding Ascii -NoNewline
    Set-Content -LiteralPath (Join-Path $nonemptyNested "child.txt") `
        -Value "synthetic-child" -Encoding Ascii -NoNewline
    $nonemptyMove = Convert-ContainedOrdinaryDirectoryToTreeSnapshot `
        -OwnershipToken $nonemptyMoveMutable
    $nonemptyManifest = $nonemptyMove.Manifest
    $nonemptySource = $nonemptyMove.Candidate
    $nonemptyDestination = Join-Path $testRoot "nonempty-move-destination"
    $nonemptyMove = Move-ContainedOrdinaryDirectory `
        -OwnershipToken $nonemptyMove `
        -DestinationTrustedRoot $testRoot `
        -Destination $nonemptyDestination `
        -DestinationRootOwnership $testRootOwnership
    if ((Test-Path -LiteralPath $nonemptySource) -or
        -not (Test-Path -LiteralPath (Join-Path $nonemptyDestination "nested\child.txt")) -or
        $nonemptyMove.Manifest -cne $nonemptyManifest -or
        $nonemptyMove.Snapshot.Manifest -cne $nonemptyManifest -or
        -not [String]::Equals(
            $nonemptyMove.Snapshot.Path,
            [IO.Path]::GetFullPath($nonemptyDestination),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "A nonempty Windows tree snapshot did not move and relock exactly."
    }
    Assert-ContainedOrdinaryTreeSnapshot -OwnershipToken $nonemptyMove | Out-Null
    Remove-ContainedOrdinaryTree -OwnershipToken $nonemptyMove

    # The release helper locks an existing PyInstaller tree, rather than freezing
    # a directory created by this library. Exercise that exact root-share mode.
    $lockedMoveMutable = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "locked-move-source") `
        -TrustedRootOwnership $testRootOwnership
    $lockedMoveSource = $lockedMoveMutable.Candidate
    Set-Content -LiteralPath (Join-Path $lockedMoveSource "helper.exe") `
        -Value "synthetic-helper" -Encoding Ascii -NoNewline
    Release-ContainedOrdinaryDirectoryOwnership -OwnershipToken $lockedMoveMutable
    $lockedMove = New-ContainedPromotableOrdinaryTreeSnapshot `
        -TrustedRoot $testRoot -Candidate $lockedMoveSource
    $lockedManifest = $lockedMove.Manifest
    $lockedMoveDestination = Join-Path $testRoot "locked-move-destination"
    $lockedMove = Move-ContainedOrdinaryDirectory `
        -OwnershipToken $lockedMove `
        -DestinationTrustedRoot $testRoot `
        -Destination $lockedMoveDestination `
        -DestinationRootOwnership $testRootOwnership
    if ((Test-Path -LiteralPath $lockedMoveSource) -or
        -not (Test-Path -LiteralPath (Join-Path $lockedMoveDestination "helper.exe")) -or
        $lockedMove.Manifest -cne $lockedManifest) {
        throw "A locked existing Windows tree did not move and relock exactly."
    }
    Assert-ContainedOrdinaryTreeSnapshot -OwnershipToken $lockedMove | Out-Null
    Remove-ContainedOrdinaryTree -OwnershipToken $lockedMove

    # Exercise the exact native state after rename but before descendant relock.
    # Reflection is test-only: it makes this otherwise internal failure boundary
    # deterministic without a timing race or a production injection hook.
    $relockMutable = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "relock-source") `
        -TrustedRootOwnership $testRootOwnership
    Set-Content -LiteralPath (Join-Path $relockMutable.Candidate "original.txt") `
        -Value "synthetic-original" -Encoding Ascii -NoNewline
    $relockToken = Convert-ContainedOrdinaryDirectoryToTreeSnapshot `
        -OwnershipToken $relockMutable
    $relockSource = [string]$relockToken.Candidate
    $relockDestination = Join-Path $testRoot "relock-destination"
    # PowerShell 5.1 wraps properties retrieved from a PSCustomObject in
    # PSObject. Reflection does not unwrap those values for String parameters,
    # so keep this test-only invocation type-exact with the native method.
    $relockIdentity = [string]$relockToken.Identity
    $relockRootPath = [string]$testRoot
    $relockDestinationPath = [string]$relockDestination
    $relockDestinationName = [string][IO.Path]::GetFileName($relockDestination)
    $unrelatedSibling = Join-Path $testRoot "relock-unrelated"
    [IO.Directory]::CreateDirectory($unrelatedSibling) | Out-Null
    Set-Content -LiteralPath (Join-Path $unrelatedSibling "keep.txt") `
        -Value "synthetic-keep" -Encoding Ascii -NoNewline

    $capabilityAssembly = [TVTimeWindowsPackaging.DirectoryCapabilities].Assembly
    $nativeType = $capabilityAssembly.GetType(
        "TVTimeWindowsPackaging.WindowsPackagingNative",
        $true
    )
    $treeType = $capabilityAssembly.GetType(
        "TVTimeWindowsPackaging.WindowsPackagingTree",
        $true
    )
    $staticInternal = [Reflection.BindingFlags]::Static -bor `
        [Reflection.BindingFlags]::NonPublic
    $instanceInternal = [Reflection.BindingFlags]::Instance -bor `
        [Reflection.BindingFlags]::NonPublic
    $revalidateMethod = $treeType.GetMethod("Revalidate", $staticInternal)
    $releaseDescendantsMethod = $relockToken.Snapshot.GetType().GetMethod(
        "ReleaseDescendants",
        $instanceInternal
    )
    $renameRetainedMethod = $nativeType.GetMethod("RenameRetainedRoot", $staticInternal)
    $moveToMethod = $relockToken.Snapshot.GetType().GetMethod("MoveTo", $instanceInternal)
    $relockMethod = $treeType.GetMethod("RelockAfterMove", $staticInternal)
    $testRootNative = Get-OwnershipNativeCapability -OwnershipToken $testRootOwnership

    $revalidateMethod.Invoke(
        $null,
        [object[]]@($relockToken.Snapshot, $relockSource)
    ) | Out-Null
    $releaseDescendantsMethod.Invoke($relockToken.Snapshot, $null) | Out-Null
    $movedRelockPath = [string]$renameRetainedMethod.Invoke(
        $null,
        [object[]]@(
            $relockToken.Snapshot.Handle,
            $relockIdentity,
            $testRootNative.Handle,
            $relockRootPath,
            $relockDestinationName
        )
    )
    $moveToMethod.Invoke(
        $relockToken.Snapshot,
        [object[]]@($movedRelockPath)
    ) | Out-Null
    Set-Content -LiteralPath (Join-Path $relockDestination "added-after-rename.txt") `
        -Value "synthetic-added" -Encoding Ascii -NoNewline

    $postRenameRelockRejected = $false
    try {
        $relockMethod.Invoke(
            $null,
            [object[]]@($relockToken.Snapshot, $relockDestinationPath)
        ) | Out-Null
    } catch {
        $postRenameRelockRejected = `
            $_.Exception.InnerException.Message -like "*immutable manifest*"
    }
    if (-not $postRenameRelockRejected -or
        -not [String]::Equals(
            $relockToken.Snapshot.Path,
            [IO.Path]::GetFullPath($relockDestination),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "A post-rename snapshot mutation did not fail relocking exactly."
    }

    # Mirror the production catch reconciliation, then prove failure cleanup
    # deletes only the moved tree through its retained root capability.
    $relockToken.TrustedRoot = [IO.Path]::GetFullPath($testRoot)
    $relockToken.Candidate = [IO.Path]::GetFullPath($relockDestination)
    $relockRootHandle = $relockToken.Snapshot.Handle
    $relockCleanupReportedMutation = $false
    try {
        Remove-ContainedOrdinaryTree -OwnershipToken $relockToken
    } catch {
        $relockCleanupReportedMutation = $_.Exception.Message -like "*immutable manifest*"
    }
    if (-not $relockCleanupReportedMutation -or
        (Test-Path -LiteralPath $relockSource) -or
        (Test-Path -LiteralPath $relockDestination) -or
        $relockRootHandle.IsClosed -eq $false -or
        -not (Test-Path -LiteralPath (Join-Path $unrelatedSibling "keep.txt") -PathType Leaf)) {
        throw "Post-rename relock failure cleanup did not target the exact moved tree."
    }

    $snapshotMutable = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "snapshot-source") `
        -TrustedRootOwnership $testRootOwnership
    Set-Content -LiteralPath (Join-Path $snapshotMutable.Candidate "helper.exe") `
        -Value "synthetic-helper" -Encoding Ascii -NoNewline
    $snapshotSource = $snapshotMutable.Candidate
    $snapshot = Convert-ContainedOrdinaryDirectoryToTreeSnapshot `
        -OwnershipToken $snapshotMutable
    $mutationRejected = $false
    try {
        Set-Content -LiteralPath (Join-Path $snapshotSource "helper.exe") `
            -Value "tampered" -Encoding Ascii -NoNewline
    } catch {
        $mutationRejected = $true
    }
    if (-not $mutationRejected) {
        throw "The locked helper snapshot permitted byte mutation."
    }
    $addedMember = Join-Path $snapshotSource "added.txt"
    Set-Content -LiteralPath $addedMember `
        -Value "tampered" -Encoding Ascii -NoNewline
    $additionDetected = $false
    try {
        Assert-ContainedOrdinaryTreeSnapshot -OwnershipToken $snapshot | Out-Null
    } catch {
        $additionDetected = $_.Exception.Message -like "*immutable manifest*"
    }
    if (-not $additionDetected) {
        throw "Post-consumer revalidation did not detect an added directory member."
    }
    Remove-Item -LiteralPath $addedMember -Force
    Assert-ContainedOrdinaryTreeSnapshot -OwnershipToken $snapshot | Out-Null
    $snapshotDestination = Join-Path $testRoot "snapshot-copy"
    Copy-Item -LiteralPath $snapshotSource -Destination $snapshotDestination -Recurse
    $snapshotCopy = New-ContainedOrdinaryTreeSnapshot `
        -TrustedRoot $testRoot -Candidate $snapshotDestination
    if ($snapshotCopy.Manifest -cne $snapshot.Manifest) {
        throw "A byte-identical helper copy did not preserve its canonical manifest."
    }
    Remove-ContainedOrdinaryTrees -OwnershipTokens @($snapshotCopy, $snapshot)

    $outsideMarker = Join-Path $outside "synthetic-marker.txt"
    Set-Content -LiteralPath $outsideMarker -Value "synthetic" -Encoding Ascii -NoNewline
    $junctionTree = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "junction-tree") `
        -TrustedRootOwnership $testRootOwnership
    $junction = Join-Path $junctionTree.Candidate "linked"
    & cmd.exe /d /c "mklink /J `"$junction`" `"$outside`"" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "The synthetic NTFS junction could not be created." }
    & attrib.exe +R $junction /L | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "The synthetic NTFS junction could not be marked read-only."
    }
    Remove-ContainedOrdinaryTree -OwnershipToken $junctionTree
    if (-not (Test-Path -LiteralPath $outsideMarker -PathType Leaf)) {
        throw "Identity-bound cleanup traversed an NTFS junction."
    }

    $first = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "first-cleanup") `
        -TrustedRootOwnership $testRootOwnership
    $second = New-ContainedOrdinaryDirectory `
        -TrustedRoot $testRoot -Candidate (Join-Path $testRoot "second-cleanup") `
        -TrustedRootOwnership $testRootOwnership
    $badFirst = [pscustomobject]@{
        TrustedRoot = $first.TrustedRoot
        Candidate = $first.Candidate
        Identity = [string]::new('0', 48)
        Capability = $first.Capability
        Snapshot = $null
        Manifest = $null
    }
    $primary = $null
    try { throw "synthetic primary build failure" } catch { $primary = $_ }
    $preservedPrimary = $false
    try {
        Remove-ContainedOrdinaryTrees `
            -OwnershipTokens @($badFirst, $second) `
            -PrimaryError $primary
    } catch {
        $preservedPrimary = $_.Exception.Message -like "*synthetic primary build failure*"
    }
    if (-not $preservedPrimary -or (Test-Path -LiteralPath $second.Candidate)) {
        throw "Windows packaging cleanup masked the primary error or skipped a later target."
    }
    if (-not $first.Capability.Handle.IsClosed) {
        throw "Multi-target cleanup left a rejected native handle open."
    }
    $firstPath = $first.Candidate
    Release-ContainedOrdinaryDirectoryOwnership -OwnershipToken $first
    $firstSnapshot = New-ContainedOrdinaryTreeSnapshot `
        -TrustedRoot $testRoot -Candidate $firstPath
    Remove-ContainedOrdinaryTree -OwnershipToken $firstSnapshot
} catch {
    $bodyError = $_
} finally {
    Remove-ContainedOrdinaryTrees `
        -OwnershipTokens @($testRootOwnership, $outsideOwnership) `
        -PrimaryError $bodyError
    [IO.Directory]::Delete($base)
}

Write-Output "Windows packaging identity and cleanup checks passed."
