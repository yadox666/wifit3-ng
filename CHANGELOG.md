# Changelog

This changelog describes the additional functionality in this enhanced local
build compared with the original
[derv82/wifit3](https://github.com/derv82/wifit3) source tree.

## Unreleased - 2026-09-26

### Added

#### Wi-Fi discovery and presentation

- Added switchable AP and client scanner views.
- Added a redesigned client table with association, AP, manufacturer, signal,
  packet count, last-seen age, and probe-request information.
- Added AP and client manufacturer resolution through an updateable IEEE OUI
  database.
- Added manual OUI updates to the startup device-selection screen.
- Added monthly OUI refresh control.
- Added consistent signal-strength colours across Wi-Fi and Bluetooth.
- Added configurable AP inactivity expiry, including a Never option.
- Added scanner pause, filters, stable sorting, reverse sorting, and exports.
- Added fixed channel selection under the Channel Lock name.
- Added AP infrastructure grouping for confirmed identical SSIDs.
- Added aggregated infrastructure channels, signal, beacons, clients,
  manufacturers, security, and WPS data.
- Added Enter and `i` controls for expanding and collapsing infrastructures.

#### Advertised information

- Added AP uptime and advertised-country display.
- Added detailed AP radio, timing, BSS load, channel-width, spatial-stream,
  power, cipher, AKM, PMF, roaming, vendor-IE, WPS, and identity information.
- Added detailed client radio capabilities, selected AKM, PMF, manufacturer,
  randomized-MAC status, association, limits, and probe requests.
- Added a visible `WPS Info` key action while retaining the magnifying-glass
  control.

#### Passive WPA-Enterprise analysis

- Added parsing for visible non-key EAPOL/EAP packets.
- Added recognition for Identity, EAP-MD5, EAP-TLS, LEAP, EAP-TTLS, PEAP,
  EAP-MSCHAPv2, EAP-FAST, EAP-AKA', and TEAP.
- Added bounded outer EAP-TLS fragment reassembly.
- Added passive TLS version, selected cipher, certificate fingerprint,
  validity, signature-algorithm, key-algorithm, and key-size inspection.
- Added structured findings with severity, evidence, and confidence.
- Added detection for WEP, legacy WPA, TKIP, weak PMF posture, EAP-MD5, LEAP,
  direct EAP-MSCHAPv2, obsolete TLS, weak TLS ciphers, expired or not-yet-valid
  certificates, MD5/SHA-1 certificate signatures, and short RSA keys.
- Added `!WEAK` scanner markers and Focus security-risk messages.
- Added Enterprise observations to AP details, client details, Client Focus,
  and target metadata.
- Added privacy controls that discard EAP Identity values and non-TLS
  credential-response bodies from the in-memory Enterprise profile.

#### Focused capture and Vault

- Added `x` packet-capture control to AP Focus.
- Added standard IEEE 802.11 libpcap streaming output.
- Added AP-BSSID filtering that retains both ToDS and FromDS traffic.
- Added a dedicated Client Focus screen and exact-client capture filtering.
- Added automatic PCAP capture for locked AP and associated-client targets.
- Added configurable capture size, rotation, and part limits.
- Added PCAP indexing, grouping, and display in Vault.
- Added blinking red `PCAP RECORDING` indicators to AP and Client Focus.

#### Saved targets

- Added private, versioned `targets.json` storage with atomic writes.
- Added Wi-Fi AP, Wi-Fi client, and Bluetooth device target types.
- Added target aliases and full observed-detail snapshots.
- Added `New Target` actions to Wi-Fi and Bluetooth scanners.
- Added Save & Continue, Save & Lock, and Cancel actions.
- Added automatic filling of previously empty target fields.
- Added optional automatic target locking.
- Added manual target override and one active lock per session.
- Added association waiting for unassociated client targets without estimating
  a channel.
- Added target reacquisition timeout and Bluetooth reconnect attempts.
- Added red `!` target markers in scanner tables even when auto-lock is off.
- Added target management in Preferences: rename, enable/disable, reorder, and
  delete.

#### Bluetooth and BLE

- Added centered Bluetooth startup selection with a `b` shortcut.
- Added a redesigned Bluetooth table with fixed identity and activity columns.
- Added signal, advertisement, interval, first-seen, last-seen, manufacturer,
  services, type, and identifier fields.
- Added Bluetooth filters, sorting, reverse sorting, and CSV export.
- Added approximate grouping and expansion for anonymous Apple privacy
  identifiers without merging their identities.
- Added read-only, no-pairing Bluetooth Focus and GATT inspection.
- Added service, characteristic, value, notification, traffic, and exposure
  displays.
- Added active-adapter and scanner-health diagnostics.
- Added exact Bluetooth target matching and read-only auto-connect.
- Added rotating JSONL advertisement and GATT-event capture for locked targets.
- Added a blinking red `BLE EVENT RECORDING` indicator.

#### Hidden SSID history

- Added private, versioned `hidden_ssids.json` storage with atomic writes.
- Added persistence of SSIDs revealed after an AP was observed hidden.
- Added exact-BSSID historical SSID autocomplete.
- Added reveal method and first/last reveal timestamps.
- Added yellow `?` marking until a historical SSID is observed again.
- Excluded unconfirmed historical names from SSID infrastructure grouping.

#### Navigation, preferences, and diagnostics

- Added centered, same-line Wi-Fi and Bluetooth startup buttons.
- Added coloured `w` and `b` startup shortcuts.
- Added improved startup spacing and wider device information layouts.
- Changed global quit from `q` to `Ctrl+Q`.
- Added `Escape` navigation from Wi-Fi back to device selection.
- Restricted Vault to Wi-Fi mode.
- Added About and Targets actions to Preferences.
- Added automatic update checking against the enhanced fork's
  `yadox666/wifit3` GitHub release API without automatic download or
  installation.
- Added configurable active-action confirmation and intensity.
- Moved WPS PBC automation into Preferences.
- Added consistent adapter diagnostics for Wi-Fi and Bluetooth.

### Changed

- Renamed Channel Filter to Channel Lock.
- Moved OUI updating from the Wi-Fi scanner to the startup screen.
- Moved About into Preferences.
- Moved WPS PBC automation out of the bottom action menu and into Preferences.
- Improved AP, client, Bluetooth, Focus, side-panel, and footer layouts.
- Improved dark-theme contrast for actionable identity and client fields.
- Split unstable Bluetooth activity text into fixed aligned columns.
- Preserved distinct hotkeys for WPS Info and WPS PIN.
- Standardised capture filenames so focused PCAP files sort with other Vault
  artifacts.
- Standardised signal colour semantics across all scanner and Focus screens.

### Privacy and security

- Added `.gitignore` coverage for targets, hidden SSID history, Bluetooth event
  logs, captures, scan exports, and other local wireless artifacts.
- Added best-effort private file permissions for target, hidden-SSID, and
  Bluetooth event files.
- Kept Bluetooth matching exact for saved targets; approximate rotating
  identifiers are never treated as confirmed identities.
- Kept Bluetooth connections read-only and disabled pairing.
- Limited EAP-TLS reassembly buffers and certificate counts.
- Avoided persisting EAP Identity values and credential-response payloads in
  Enterprise profiles.
- Did not add automated rogue-RADIUS or credential-validation attacks.

### Known limitations

- Bleak does not expose raw BLE link-layer packets. Bluetooth target capture is
  JSONL advertisement/GATT evidence, not PCAP.
- PEAP, TTLS, and FAST inner methods are encrypted and cannot be identified
  passively.
- Passive scanning cannot determine whether a client validates the RADIUS
  server certificate.
- A common Wi-Fi SSID does not prove common ownership.
- Similar or rotating Bluetooth advertisements do not prove a common physical
  device.
- Monitor-mode reception may miss weak client transmissions even while fixed
  to the correct AP channel.
