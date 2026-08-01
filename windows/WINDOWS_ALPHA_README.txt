TV Time Backup Extractor for Windows
v0.3.1-alpha.1 tester build

This experimental x64 build is for people who want to test the native Windows app.
It works offline and does not upload recovery data.

Requirements

- Windows 10 version 1809 or later for supported Android sources and official exports.
- Windows 11 x64 for encrypted iPhone or iPad backup recovery.
- BitLocker or Windows device encryption on the app storage volume.
- A source stored in a private local NTFS folder, outside cloud-sync and shared folders.

Install

1. Verify the ZIP against the published SHA256SUMS-Windows file.
2. Extract the complete ZIP to a private local folder.
3. Right-click Install-Windows-Alpha.ps1 and run it with PowerShell.
4. Read the certificate notice, type INSTALL, and approve the Windows trust prompt.

The package uses a project-specific self-signed certificate because this is an alpha tester build.
The bundle contains only the public certificate. It does not contain the signing private key.

Testing and support

Use synthetic data or your own authorized local source. Do not upload or attach a backup, export,
database, output tree, report, completion marker, recovered title, account detail, screenshot of
recovered content, or debug trace.

If recovery fails, copy the app's Safe Diagnostics codes. Those codes use a fixed vocabulary and
do not include paths, titles, identifiers, passwords, counts, or raw error messages.

Opening a report can add its filename to browser or viewer history and Windows Recent Items.

Remove

Copy any reports you want to keep before uninstalling. Windows can remove the app's private local
storage with the package. Run Uninstall-Windows-Alpha.ps1, type REMOVE, and approve the prompt to
remove the app and its exact alpha certificate. On a shared PC, the certificate remains until the
last Windows account removes the same release package.
