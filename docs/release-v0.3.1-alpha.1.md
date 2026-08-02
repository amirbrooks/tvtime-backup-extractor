# v0.3.1-alpha.1 release record

## Current status

This prerelease is not published. The candidate must pass every gate below from one clean commit
before a tag or public asset is created. v0.2.0 remains the latest stable release.

The planned artifact set contains:

- signed, notarized, and stapled DMGs for Apple silicon and Intel Macs;
- a downloadable Windows x64 tester bundle with a signed MSIX, public certificate, guarded install
  and removal scripts, license notices, a source-bound manifest, and checksums; and
- verified Python wheel and source packages for Python 3.10 through 3.13.

## Windows tester scope

The Windows app supports official exports and compatible local Android sources on Windows 10
version 1809 or later. Encrypted iPhone and iPad backup recovery requires Windows 11 x64. Every
route requires private local NTFS storage and BitLocker or Windows device encryption for the app's
private output volume.

The bundle uses a project-specific self-signed certificate. Installation displays that fact and
requires explicit certificate trust. The bundle contains only the public certificate. The signing
private key is created for the build, used once, and removed before the artifact is uploaded.

The app remains experimental. Hosted installation and launch smoke do not prove every physical
device, backup schema, NTFS configuration, or UI path. Testers provide the missing device coverage.

## Privacy and diagnostics

Recovery remains local and offline. The application contains no network client, telemetry, AI,
machine-learning feature, or WebView. The final MSIX membership scan rejects payload names associated
with those features while retaining required text-only dependency notices.

Safe Diagnostics uses a fixed code vocabulary. It never contains paths, filenames, titles,
identifiers, passwords, counts, helper stderr, recovered content, or free-form errors. Testers must
not upload a backup, export, database, output tree, report, marker, screenshot of recovered content,
or debug trace.

## Candidate gates

1. Freeze one clean commit and verify its exact Git tree.
2. Pass the complete Python, Swift, formatting, privacy, source-package, and hosted CI gates.
3. Build the Windows package from a verified Git archive with pinned Python 3.13.12, .NET SDK
   8.0.423, .NET runtime 8.0.29, locked NuGet dependencies, and recorded lock digests.
4. Verify exact signed MSIX membership, the bound notice set, public certificate, block map,
   manifest, checksums, and absence of private build paths or signing keys. Keep the final
   binary-to-component inventory listed as an alpha limitation.
5. Install, launch-smoke, remove, and reverify the Windows bundle on a hosted Windows x64 runner.
6. Build, sign, notarize, staple, Gatekeeper-assess, and reverify both Mac DMGs.
7. Build and verify the Python wheel and source archive from the same commit.
8. Upload the complete set to a draft prerelease, download every asset into a fresh directory, and
   repeat the applicable checks before publication.

## Publication sequence

After every gate passes:

1. Create annotated tag `v0.3.1-alpha.1` on the reviewed commit and verify its peeled target.
2. Push only the tag and confirm the remote target is unchanged.
3. Create a draft GitHub prerelease with the verified tag.
4. Upload the complete Mac, Windows, and Python artifact set.
5. Download and reverify every draft asset.
6. Publish as a prerelease while keeping v0.2.0 marked Latest.
7. Record the published status on main only after GitHub confirms publication.
