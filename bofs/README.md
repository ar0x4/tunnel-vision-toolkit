# GSA Beacon Object Files

BOFs for reconnaissance and token extraction on Microsoft Global Secure Access enrolled Windows devices. Written for [BRC4](https://bruteratel.com/) (`coffee` entry point, `BadgerDispatch` output).

## BOFs

### gsa-token-theft/gsa_enum

Full GSA reconnaissance. Enumerates:

- **Installation** — binary paths, file versions, subdirectories
- **Services** — status of all four GSA Windows services
- **Processes** — running GSA process PIDs and thread counts
- **Registry** — HKLM and HKCU configuration values
- **Security posture** — `RestrictNonPrivilegedUsers`, `HideDisableButton`, mTLS cert, bypass flags
- **Forwarding profile** — tenant ID, enabled channels (M365/Private/Internet), rule counts, edge server, full JSON dump

No arguments required. Runs as current user (non-admin sufficient for most checks).

### gsa-token-theft/gsa_tbres_steal

Extracts GSA authentication tokens from the Windows TokenBroker cache:

1. Scans `%USERPROFILE%\AppData\Local\Microsoft\TokenBroker\Cache\*.tbres`
2. Finds DPAPI-protected response blobs (`IsProtected: true`)
3. Decrypts via `CryptUnprotectData` (works in the token owner's user context)
4. Scans decrypted data for JWTs matching GSA audiences
5. Outputs token type (TUNNEL/PORTO/APS), audience, scope, expiry, and full JWT

**Requirements:** Must run as the user who owns the TokenBroker cache. DPAPI decryption uses the user's credentials — running as a different user or SYSTEM will fail.


## Building

Requires MinGW cross-compiler:

```bash
# Install cross-compiler (Debian/Ubuntu)
sudo apt install gcc-mingw-w64-x86-64 gcc-mingw-w64-i686

# Build BOFs
cd bofs/gsa-token-theft && make
```

Output: `out64/*.o` (x64) and `out86/*.o` (x86) object files, ready to load in BRC4.

## Porting to Cobalt Strike

The BOFs use BRC4's `BadgerDispatch` for output and `BadgerAlloc`/`BadgerFree` for memory. To port to Cobalt Strike:

- Replace `BadgerDispatch` → `BeaconPrintf`
- Replace `BadgerAlloc` → `intAlloc`
- Replace `BadgerFree` → `intFree`
- Replace `BadgerMemcpy/Memset/Strcmp` → standard CRT equivalents
- Change entry point from `coffee` → `go`
- Replace `badger_exports.h` with Cobalt Strike's `beacon.h`
