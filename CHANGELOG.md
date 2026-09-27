# Changelog

This changelog describes the additional functionality in this enhanced local
build compared with the original
[derv82/wifit3](https://github.com/derv82/wifit3) source tree.

## 0.3.6 - 2026-09-27

### Added

- Added an automated probe honeypot for directed client probes. After selecting
  an observed SSID, `OPEN` or `WPA2-PSK`, and a one-to-five-minute duration,
  WiFiT3 chooses a spoof-capable interface, the observed channel, and a random
  local BSSID.
- Added separate probe, Open-System authentication, association, and DHCP
  Discover/Request evidence stages. The test serves no DHCP, DNS, or Internet,
  performs no deauthentication, and records every requesting client.
- Added a completion summary listing every observed client MAC with its probe,
  authentication, association, EAPOL M2, and DHCP counters. The originating
  client is marked as `ORIGIN` while every other requesting client is answered
  and tracked. Directed probes and wildcard scans are counted separately, and
  locally administered addresses are marked as possibly randomized.
- WPA2 honeypots send M1 after association and save captured M1/M2 material to
  Vault in Hashcat 22000 form and, when enabled, PCAP.
- WPA2 honeypots prefer a PSK-compatible RSN profile derived from a live
  same-SSID AP, then from bounded prior JSON scan exports, before falling back
  to generic WPA2-PSK/CCMP. Scan exports now retain the raw RSN IE for reuse.
- Added private, bounded `wifi_profiles.json` persistence for automatically
  observed secure beacon profiles. WPA2 honeypots reuse stored ciphers, PMF
  capability, ERP/HT/VHT/extended capabilities, and WMM with channel-safe
  normalization; unsupported SAE/RSNXE and 802.11r Mobility Domain claims are
  intentionally omitted.
- Clarified WPA2 Open-System authentication as a pre-association stage and made
  runs without M2 finish with `NO M2 CAPTURED · nothing saved to Vault`.
- Added per-SSID probe channel, recency, and count tracking for Wi-Fi clients.
- Generated honeypot APs now remain visible as separate, red, explicitly
  owned fake-AP rows in the scanner while active and after stopping.
- Persisted directed client probes in the private `hidden_ssids.json` history
  with client, SSID, channel, count, and timing fields. Probe records remain
  separate from confirmed BSSID-to-SSID mappings.
- Added an unlimited-parts option for Wi-Fi PCAP and Bluetooth target capture
  rotation.
- Kept infrastructure (`I`) restricted to the AP table while making Vault
  (`V`) available from both AP and Clients tables.
- Restricted the probe honeypot (`A`) footer action to the Clients table.

#### Passive open-network metadata

- Added capture-time passive analysis for confirmed unencrypted `OPEN` APs.
- Added bounded decoders for clear-text LLC/SNAP, ARP, IPv4, IPv6, UDP, TCP,
  DHCP, and IPv6 Router Advertisements.
- Added AP-level and per-client observations for IPv4/IPv6 addresses and
  ranges, gateways, DHCP servers, DNS servers, domains, leases, and expiry.
- Added complete deduplicated AP-level and per-client website lists from clear-text DNS
  questions, TLS SNI, and HTTP requests. Full HTTP URLs replace SNI origins
  and DNS-only placeholders for the same host; distinct paths remain separate.
- Added DHCP broadcast-reply correlation through the DHCP client hardware
  address.
- Added captive-portal evidence from DHCP option 114, IPv6 option 37, plain
  HTTP redirects, and bounded portal-like DNS/TLS SNI hints.
- Added `Observed`, `Declared`, and `Suspected` portal states with conservative
  evidence-based likelihood scores; no evidence is shown as unknown rather
  than as a false zero probability.
- Added source, confidence, first/last-seen time, expiry, conflict retention,
  and historical marking for network facts.
- Added expandable live/history NETWORK panels to AP Focus and Client Focus.
- Extended the AP Focus client detail popup with client-specific IPv4/IPv6
  addresses, ranges, gateways, DHCP/DNS servers, domains, connectivity, and
  captive-portal evidence. Missing client IPs are explicit, and relevant
  fallback infrastructure values are clearly labeled as AP-wide.
- Added private, versioned, per-BSSID `<ssid>_<bssid>_network.json` files
  beside capture/key artifacts.
- Added atomic and debounced network-metadata persistence that merges following
  live-capture observations across sessions.

#### Fake-Connect

- Added an open-AP **Fake-Connect** action and `o` Focus shortcut.
- Added randomized temporary client MAC generation, Open-System
  authentication, and association for confirmed open APs with known SSIDs.
- Added a persistent associated state so an otherwise-idle AP can emit traffic
  while focused capture is active.
- Added up to three bounded DHCP Discover probes after association.
- Added DHCP Offer summaries for proposed address, gateway, DNS, and DHCP
  server.
- Added bounded DHCP Request/ACK and best-effort Release support for one
  temporary connectivity-test lease.
- Added gateway ARP, advertised-DNS, TCP, and HTTP 204 connectivity checks
  against the explicitly disclosed `connectivitycheck.gstatic.com` endpoint.
- Added Internet-confirmed, limited/inconclusive, portal-observed, and
  portal-suspected outcomes to the AP/client NETWORK panels and metadata JSON.
- Reused one randomized Fake-Connect MAC per AP during a session to avoid
  accumulating pending DHCP Offers and triggering common router rate limits.
- Added immediate merging of received Offers into the AP and temporary-client
  NETWORK sections, including subnet/range, domain, lease, and captive-portal
  options, whether or not focused PCAP recording is active.
- Added immediate atomic persistence of Fake-Connect Offer metadata to the
  per-BSSID network JSON.
- Added a **Disconnect** state that sends a client-leaving frame and removes
  the temporary forged-client registration.
- Added active-action confirmation and clear impact text before Fake-Connect.
- Kept Fake-Connect unavailable for encrypted/OWE APs and hidden APs with no
  exact historical name or named same-radio sibling.
- Added an explicitly uncertain `SSID [guess]` association attempt for hidden APs
  whose strongest named sibling supplies the only available SSID candidate.
- Extended **Fake-Connect** to WEP APs. It performs Open-System authentication
  and association with the Privacy capability set, then deliberately stops
  before DHCP or connectivity traffic because WEP data frames require the key.
- Kept the WEP temporary association active until **Disconnect**, Focus exit,
  AP disconnect, or campaign stop, using the same client-leaving cleanup as the
  open-network path.
- Added explicit fake-client registration in the shared client model while a
  Fake-Connect association is active. The synthetic client is removed on every
  campaign exit path and remains excluded from scanner counts, handshakes, and
  normal captured-client processing.
- Added a yellow `◈` fake-client badge and `Fake-Connect` label in the
  right-side CLIENTS panel. Its unknown signal is rendered as a dash, and its
  per-client deauthentication control remains disabled; the campaign's
  **Disconnect** action owns its lifecycle.
- Added a steady cyan L-shaped connector while one or more clients are shown.
  It starts beside the visible router body, one row below
  the former alignment, and joins the center of the CLIENTS panel's top border
  without an arrow. It adapts to either left-to-right or right-to-left layouts
  and disappears when the AP has no connected clients.

#### Channel operation and tuning safety

- Added parsing of the active HT 20/40 MHz width, secondary-channel direction,
  and derived center channel from the HT Operation element.
- Added parsing of active VHT 80/160/80+80 MHz width and both advertised center
  frequency segments without treating either segment as a primary channel.
- Added a plain-language Focus readout such as `channel 36 · 80 MHz`.
- Added technical AP details that separately show the primary channel, active
  width, secondary channel above/below, center segment(s), and supported radio
  capabilities.
- Added explicit detection of contradictory DS Parameter and HT Operation
  primary-channel advertisements. The scanner then uses the channel on which
  the frame was actually received and exposes the conflict in technical
  details.
- Added a hard campaign guard that prevents authentication, association, or
  injection from continuing when the selected adapter cannot confirm the
  requested channel.

### Changed

- Stopped using the VHT center-frequency segment as a last-resort tune target.
  For example, an 80 MHz AP on primary channel 36 may advertise center segment
  42; Focus now stays on primary channel 36 instead of attempting channel 42.
- Separated active operating width from the accumulated set of widths an AP or
  client advertises as supported.
- Replaced the ambiguous `PORTAL UNLIKELY` summary with
  `NO CAPTIVE PORTAL DETECTED` after a successful HTTP 204 connectivity check.
- Changed the scanner so the highlight follows the same selected AP BSSID or
  client MAC when live sorting moves it to another row.
- Kept hidden `[guess]` rows directly below the named sibling that supplied
  their displayed SSID, regardless of the active sort column or direction.
- Changed `OPEN` encryption labels to red and added the scanner `!WEAK` marker.
- Added live rotated-file count and total saved megabytes to AP and Client
  `PCAP RECORDING` indicators.
- Extended hidden-SSID history to remember every confirmed BSSID-to-SSID
  sighting, including APs first observed with a visible SSID.
- Added same-radio sibling SSID guesses to Focus, matching the scanner's yellow
  `SSID [guess]` presentation.
- Added yellow uncertainty styling for exact-BSSID historical names in Focus.

### Privacy and security

- Network metadata files use best-effort private permissions and atomic
  replacement.
- Passive metadata storage is bounded by client, non-website fact, option,
  field, and individual URL-length limits. Website lists retain every
  deduplicated URL.
- DHCP hostnames/client identifiers, HTTP bodies, cookies, credentials,
  fragments, and sensitive query values are not retained. Sensitive query
  values are persisted as `REDACTED`.
- Fake-Connect uses randomized temporary client addresses, claims at most one
  temporary lease, makes one bounded disclosed connectivity request, and sends
  DHCP Release afterward. It does not submit portal forms or transmit
  credentials.

### Known limitations

- Passive network metadata depends on traffic actually received during the
  live focused capture; beacon-only captures contain no DHCP/IP information.
- Existing PCAP files are not retrospectively analyzed to rebuild or enrich
  network metadata.
- Plain HTTP redirects can be observed, but encrypted HTTPS portal behavior
  generally cannot be passively verified.
- A sibling `SSID [guess]` is an infrastructure guess, not a confirmed SSID.
  Fake-Connect may try it after active-action confirmation, but the AP can
  reject it when the hidden VAP uses a different SSID.

## 0.3.4 - 2026-09-26

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
- Added yellow `[history]` marking until a historical SSID is observed again.
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
  `yadox666/wifit3-ng` GitHub release API without automatic download or
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
