# Atlant Control licensing

The vendored `control/web/qrcode.js` QR encoder retains Kazuhiko Arase's MIT
license; see `control/web/QRCODE-LICENSE.txt`. It is not relicensed as GPL.

Copyright (C) 2026 Atlant VPN contributors.

The original Atlant Control management code in this directory is licensed
under the GNU General Public License, version 3 only (SPDX: GPL-3.0-only).
This covers the web panel, CLI, installer, service helper, management assets
and their tests. See `LICENSE` for the full, unmodified license text.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. You may copy, modify and redistribute it under GPLv3.

The management implementation is original Atlant code. It does not include
3x-ui source code. Similar interaction patterns are not a claim of upstream
affiliation or compatibility with the Xray administration API.

This directory's license does not change the separate VPN core, Android or
Windows client licensing. The repository root Apache-2.0 license applies to
original core code; clients retain their scoped MIT licenses. Independently distributed
certificate-agent source and its dependency notices must accompany the
management distribution as required; do not omit corresponding source or
upstream licenses from a public release. No release is considered publication
ready solely because this license file has been added.
