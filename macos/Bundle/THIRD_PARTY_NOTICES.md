# Third-party notices

The macOS application bundles the following components. A release build must preserve the exact
license files collected from its frozen artifact and include them beside this notice.

- CPython — Python Software Foundation License, copied byte-for-byte from the exact reviewed
  CPython 3.13.12 source release and bound by the native-license provenance profile.
- `iphone-backup-decrypt` — MIT License, with incorporated BSD-licensed source noted upstream.
- PyCryptodome — public-domain and BSD-licensed components.
- ReportLab — BSD License.
- Bitstream Vera fonts — Bitstream Vera license. The app carries only the regular, bold, italic,
  and bold-italic Vera faces used by its private PDF report, together with the matching complete
  license text.
- Pillow and the native image libraries carried by its pinned wheel — the complete aggregate license
  text shipped by Pillow, including the notices for those vendored libraries.
- charset-normalizer — MIT License.
- OpenSSL — Apache License 2.0.
- mpdecimal — BSD 2-Clause License.
- SQLite — public-domain dedication and blessing from lines 4–9 of the pinned `sqlite3.h`; the
  checked-in notice removes each leading `**` and at most one following space, joins with LF, and
  ends with exactly one LF.
- PyInstaller bootloader — GPL-2.0-or-later with the PyInstaller bootloader exception.
- PyInstaller runtime hooks — Apache-2.0 and other licenses identified by the pinned hook package.
- altgraph and macholib — MIT License.

Project source is licensed under the repository's MIT `LICENSE` file. This notice is an inventory,
not a substitute for the complete license texts required in a downloadable release.

`Licenses/LICENSES.json` maps every non-system Mach-O path to its primary component and any embedded
components, their exact versions and shipped license texts, and a canonical SHA-256. Its canonical
Mach-O hash is computed from a private copy
using `/usr/bin/codesign --remove-signature` and must remain equal before and after signing; the
source binary is never modified. The per-architecture release manifest records SHA-256 for every
final app file, while the signed DMG and its published checksum bind the downloadable artifact
bytes.
