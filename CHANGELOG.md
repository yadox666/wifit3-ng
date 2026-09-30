# Changelog

This changelog describes the additional functionality in this enhanced local
build compared with the original
[derv82/wifit3](https://github.com/derv82/wifit3) source tree.

## Unreleased

## 0.3.11 - 2026-09-30

### Added


- **Startup Wi‑Fi adapter picker** (`DevicePicker`, first screen): one compact
  row per USB card — checkbox, chipset/product name, and inline **All | 2.4 | 5G**
  band chips. Dual-band adapters can pin AP/Clients scanner hopping to one band;
  single-band hardware shows a fixed band label from the driver `SUPPORTED_CHANNELS`
  list. Choices are remembered per physical device and apply **only** to scanner
  hopping (Focus, campaigns, and injection are unchanged). Panel width hugs content.
  Works with scanner **Channel Lock** (`c`), which further narrows the hop set.

- **Offline DB search** (startup **`O`** / **OFFLINE DB**, no radio required):
  tab-specific filter row above the AP, client, and Bluetooth history tables.
  Access points: encryption, WPS, client presence, Wi-Fi band (2.4 / 5 / 6 GHz),
  GPS, and free text (SSID, BSSID, vendor, channel, client MACs, identity
  evidence). Clients: association state, GPS, and text (MAC, vendor, linked
  SSID/BSSID). Bluetooth/BLE: device category, radio posture (BLE only, Classic
  only, or dual), and text (name, address, manufacturer, services, protocol).
  Token rules match the live scanner filter bar; **`f`** / **`/`** focus search;
  the table border shows **matched / total** record counts when narrowed.
  Filter controls use a single-line row (no wrapped dropdown labels).


- **Client Focus** now uses the spatial AP-Focus layout: adapter card, packet
  sparklines, and a station endpoint (USB-dongle art, RSSI meter, identity).
  Pressing Enter on a client row opens it; Escape returns to the Clients view.
  It shows the event log and a clients panel (with the associated AP banner and
  per-client deauth), an enabled/disabled **Probe Honeypot** button when the
  client has directed probes, and **Deauth client** / **Deauth AP** controls
  when the client is associated. A running honeypot lists the origin client and
  any others that connect.
- Scanner **GPS** column (AP and client tables) now shows a clickable globe
  icon instead of raw coordinates. Clicking it (or **Open position in Google
  Maps** in `Ctrl+D`) opens the stored fix in the default browser; coordinates
  are sent to Google only after that click.

- **GPS location history** (with a valid USB NMEA fix): observed **access points**
  keep one position cluster per BSSID. **Portable Wi-Fi clients** and
  **Bluetooth/BLE devices** keep multiple clusters; a **new cluster** is recorded
  when an observation is farther than the configured movement distance
  (Preferences, default and minimum 20 m) from every existing cluster. Within a
  cluster, updates require a meaningful improvement in signal and/or GPS
  accuracy (see **Changed**).

- **Startup Bluetooth adapter picker** (`BluetoothPicker`): supported USB HCI
  dongles appear in a second panel below Wi‑Fi with checkboxes and **BT+BLE** /
  **BT** / **BLE** tags. **`D`** / **BT/BLE Scan** starts direct Classic (+ BLE
  where supported) on the selected dongle; unchecked rows are ignored.



- **Startup SDR and GPS/GNSS panels:** HackRF devices and confirmed NMEA
  receivers appear alongside Wi-Fi and Bluetooth hardware. The GPS row shows
  manufacturer/product metadata, serial port, baud rate, NMEA/fix state,
  satellites, and accuracy; hovering any truncated row shows the complete
  text. Both panels are removed from layout when their hardware is absent.

- **Targets & whitelist library** (**`Shift+T`** globally, **`n`** / **Targets**
  on the Wi‑Fi or Bluetooth scanner with an optional row selection, **`t`** from
  Preferences): centered editor with category tabs (All, AP, STA, BLE, BT,
  Whitelist), search, a detail pane (alias, role, match mode, identifier), and
  **Add manual** for entries matched by BSSID/MAC/UUID or by SSID / Bluetooth
  name. Selecting a row that is not yet saved opens a draft with observed fields
  prefilled (alias required). Existing entries open for edit, role change, or
  delete. Storage uses `targets.sqlite3` schema v2 (`role`: target vs whitelist,
  `match_mode`: id vs name).

- **Whitelist:** devices on the whitelist are marked in live scans with a green
  **`◇`** (saved **targets** keep red **`!`**). The first time each enabled
  target or whitelist entry is seen in range during a session, a toast reports the
  alias and where it was observed (AP, client, or Bluetooth row).

- **Focus leave confirmation:** **Escape** / Back from AP Focus or Client Focus
  while campaigns, WPS/enterprise probes, honeypots, focused PCAP, or passive
  network-metadata capture are still active opens a dialog listing what is
  running; **Stop and leave** tears everything down and returns to the scanner
  (or client list); **Stay** cancels.

### Changed

- **Clear-DB** (`c`): moved from the startup device-selection footer to the
  **Offline DB** screen footer, where history is browsed. The same confirmation
  modal and `DELETE NOW!` phrase apply; tables reload after a successful clear.

- **Targets library** (`Shift+T`): removed from global app bindings; it is
  registered only on Wi-Fi/BLE scanners, Offline DB, and Focus screens (not on
  startup device selection).

- **Startup footer:** removed redundant **Enter · Start** (same as **`W`**
  / **START WI-FI**). **Enter** still activates the focused button (e.g.
  Uninstall).

- **Startup optional hardware:** **BT/BLE Scan**, **`D` · BT + BLE**, and the
  Bluetooth panel are **omitted** from the layout and footer until matching
  hardware is detected (not merely hidden). The GPS/GNSS panel follows the
  same space-saving behavior and is mounted only after valid NMEA traffic
  confirms a receiver.

- **GPS connection reporting:** removed the redundant “GPS detected” toast.
  Connection details and live fix quality now remain visible in the conditional
  startup GPS/GNSS panel and in `Ctrl+D` diagnostics.

- **5 GHz scanner hop includes DFS channels** (52–64, 100–144): dual-band
  drivers now advertise the full 5 GHz primary grid in `SUPPORTED_CHANNELS`
  (`wlan.channels.DUAL_BAND_SCAN_CHANNELS`), so AP/Clients hopping and **Channel
  Lock** (`c`) can visit DFS slots such as **60** for passive beacon capture.
  This is receive-only tuning — no radar CAC or DFS transmit infrastructure.
  **Preferences → Wi‑Fi regulatory country** still governs TX power limits where
  the driver applies regdb; it does not separately gate the hop list. 2.4-only
  adapters are unchanged.

- **Channel hop order** (`wlan.channels.scan_hop_order`): every channel on each
  card is still visited, but 2.4 GHz uses a coprime stride (for example
  1→6→11→2→7…) and 5 GHz channels are spread the same way after the 2.4 block,
  instead of sequential 1–14, so overlapping AP visibility improves without
  dropping channels. When startup per-card bands pin one adapter to 2.4 GHz and
  another to 5 GHz (`wlan.scan_plan`), each card hops only its assigned subset;
  when every card stays on **All bands**, the pool still SPREAD-partitions channels.

- AP Focus with **two or more adapters** shows a left **cards column**: both
  dongles, live tuned channel, and campaign role (AP host, deauth, or lock). When
  the on-air channel differs from the campaign's configured channel, the label
  shows both (for example `CH 8 ≠ 4`).

- Focus and scanner **event logs** (`SelectableRichLog`) follow the tail only
  when you are already scrolled to the bottom; reading or selecting older lines
  no longer jumps away when new events arrive.

- **GPS cluster update policy:** within a cluster, a stored fix is replaced only
  when the new observation dominates the old one (at least as good on RSSI and
  GPS error radius, strictly better on at least one). A stronger signal with a
  worse accuracy radius no longer overwrites a more precise position.
  **Hysteresis** (2 dB signal / 1 m accuracy) ignores sub-margin jitter so
  positions stay stable instead of rewriting on every hop.
- **Google Maps links:** AP table rows use the **best** stored fix (strongest
  RSSI, then best accuracy, then recency). Client and Bluetooth rows use the
  **latest** fix in the relevant cluster (last place the device was seen).
- WPA2/WPA2-PSK APs now keep a network-metadata store in Focus, so Fake-Connect
  DHCP, connectivity, and ARP-sweep evidence reaches each client's **NETWORK**
  popup (previously created only for open APs). Swept IPv4s also appear beside
  the vendor in the Clients panel.

- **Preferences** (`Ctrl+P`) is a centered, tabbed modal (**General**, **Scanner**,
  **Safety**, **Captures**, **GPS**, **Radio**) with a descriptive label above
  each control instead of one long scrolling form. **About** (`a`) and the
  targets library (`t`) remain available from Preferences.

- Wi‑Fi / Bluetooth scanner **`n`** opens the **targets library** (label
  **Targets**); the legacy New Target-only dialog is replaced by the editor
  flow. Auto-lock still resolves APs by BSSID or a saved SSID-name rule and
  clients by MAC.

- Manual **deauth** in AP Focus and Client Focus is refused for whitelisted AP
  BSSIDs and client MACs (warning toast). Other campaigns are not yet gated.

### Fixed

- **BLE Focus GATT reads:** characteristics that store binary data as an ASCII
  hex string (common for keys and UUID-like blobs) no longer swap labels — wire
  octets were shown as “Hex” while the hex digit text was shown as “ASCII”. The
  Value detail now shows **Payload (hex)** (parsed binary), **ASCII (from
  payload)** (printable view of those bytes, `.` elsewhere), and **Raw bytes**
  (on-air encoding). **`A`** toggles the GATT table value column between raw
  bytes and parsed payload hex where applicable.

- **MT7921AU / MT7925U warm attach:** when another driver left MediaTek firmware
  running (foreign WFDMA latch), the app now fails bring-up with an explicit USB
  **replug** instruction instead of attempting a broken warm reattach (ported
  from upstream [wifit3 v0.3.4](https://github.com/derv82/wifit3/compare/v0.3.3...v0.3.4)).

- Returning to the splash adapter picker (**Escape** from the scanner) no longer
  crashes with Textual `DuplicateIds` on `device-row-*` / `bt-row-*`: picker
  rows detach synchronously before remount when the Wi‑Fi or Bluetooth lists are
  rebuilt.

- Splash startup no longer raises `NoMatches` for `#bluetooth-usb-btn` when
  optional USB Bluetooth hardware is absent: the action is always composed on
  the startup bar and toggled with `display` when matching devices are
  detected, so `_enter_scanning_mode` can sync state on first paint.

- `WlanArray.set_channel` / `set_channel_spec` no longer retune cards **claimed**
  by an active campaign, so a EvilTwin lease channel is not undone when
  Focus retargets other pool members.


## 0.3.10 - 2026-09-28

### Added

- **Fake-Connect** on WEP APs with a recovered key (session or Vault) and on
  WPA2-PSK/CCMP APs with a captured passphrase (WPS, cracked handshake, or Vault).
  Protected paths run a 4-way handshake (WPA2), encrypt station traffic, then use
  the same bounded DHCP and connectivity probe as open networks. WEP without a
  key remains association-only. Placeholder WPS passphrases are not treated as
  usable credentials.
- WPA2 Fake-Connect now installs the group key from message 3 so broadcast DHCP
  Offers decrypt correctly on APs that do not unicast replies. The GTK is
  extracted with NIST AES Key Wrap (RFC 3394), the encryption WPA2 actually uses
  for EAPOL Key Data (validated against the RFC 3394 known-answer vector).
- Fake-Connect requests **unicast** DHCP replies (BOOTP broadcast flag cleared)
  on encrypted networks, so the Offer/ACK arrive under the pairwise key.
- Added an on-air encrypted **data-path self-check** after key install: it
  transmits an AP-acknowledged encrypted frame and confirms a MIC-valid frame
  can be decrypted from the AP, logging the write/read result.
- Fake-Connect now runs a bounded **ARP neighbour sweep** while holding the
  temporary lease: it broadcasts an ARP request to each host in the (/24-scoped,
  capped) subnet and logs the responding IP/MAC pairs with vendor and gateway
  annotations. Runs on open and encrypted networks alike. Each neighbour’s IPv4
  is merged into that client’s **NETWORK** popup and saved in AP network metadata.
- AP Focus no longer prints saved WEP/WPS/WPA passphrases in the “Existing
  captures” log; it shows a **recovered** placeholder chip instead.
- Preferences **Wi-Fi regulatory country** (ISO alpha-2) with bundled
  wireless-regdb rules applied to Mediatek connac channel domains and several
  chip TX-power paths when the OS has no cfg80211 regdom.
- Native WPA2-PSK station helpers (`wpa_station`, `station_crypto`) for the
  Fake-Connect protected data path, including AES Key Wrap for GTK install.

## 0.3.9 - 2026-09-28

### Added

- Passive website discovery now recovers **QUIC / HTTP-3** destinations. A
  self-contained, dependency-free QUIC decoder (`wlan/quic.py`) derives the
  client-Initial keys from the public Destination Connection ID, decrypts v1 and
  v2 Initial packets (AES-128-GCM payload, AES-ECB header protection, HKDF-SHA256
  key schedule), reassembles CRYPTO frames, and extracts the TLS ClientHello SNI.
  Hosts are recorded with source `quic_sni`. All crypto is validated against
  FIPS-197, McGrew GCM, and RFC 5869 test vectors.
- Passive TLS SNI parsing now performs bounded, in-order **TCP reassembly**, so a
  ClientHello split across multiple TCP segments still yields its hostname.
- Passive open-network metadata and website discovery now run for the lifetime
  of AP Focus or Client Focus, independently of optional PCAP file recording.
- MT7921AU and MT7925U Focus tuning now follows an AP's advertised 20/40 MHz
  operating channel, including the secondary-above/below and center-channel
  fields on both 2.4 and 5 GHz. The sniffer command follows upstream `mt76`;
  legacy cards continue to tune the primary 20 MHz channel.
- AP Focus now warns about a network's **cross-band (2.4/5 GHz) twin** when one is
  visible, matching by SSID or by same-OUI / near-identical BSSID (for hidden
  twins). The informational notice explicitly states that the current capture
  remains on its selected channel.
- The shared client/website search field in AP Focus now has a persistent
  outline and a keyboard-focusable `×` control that clears the query while
  keeping focus in the field.

### Fixed

- Passive website discovery now decodes bounded QoS **A-MSDU aggregates**
  instead of counting their outer data frame while discarding every contained
  DNS, TLS, HTTP, and QUIC payload.
- Power-save **Null / QoS-Null / CF** frames (no-payload data subtypes) are no
  longer counted as payload "data" on the packet-rate dashboard. They are now
  tagged `null_data`, still registering client presence and association but no
  longer inflating the data line, which previously made an idle, power-saving
  client look like it was actively transferring traffic.
- RTL8814AU monitor mode now reapplies its accept-all RCR and RX filter maps
  after a final channel lock. This prevents channel hopping from leaving the
  adapter receiving management/Null frames while silently omitting payload data
  from focused PCAP captures.

## 0.3.8 - 2026-09-28

### Added

- Added direct USB support for the Sena Parani-UD100 / CSR BlueCore4-ROM
  (`0a12:0001`). Its Bluetooth 2.0 ROM is correctly treated as Classic-only,
  while the operating-system Bleak scanner continues BLE discovery
  concurrently.
- Added read-only Bluetooth Classic remote-name resolution and public SDP
  browsing over the dedicated USB HCI controller. The bounded transport reads
  controller ACL limits, applies packet-credit flow control, handles split and
  coalesced USB ACL packets, reassembles L2CAP fragments, completes
  bidirectional channel configuration, validates SDP continuations/data
  elements, and performs best-effort L2CAP/HCI teardown.
- Classic SDP never accepts pairing, stores link keys, opens RFCOMM profiles,
  or writes remote profile data. PIN, link-key, Secure Simple Pairing, passkey,
  and OOB requests receive explicit negative replies.
- Added a Classic Focus view with inquiry metadata, probable BT/BLE identity
  links, discovered service classes, and live HCI health counters. Classic
  Focus leaves split direct-Classic and system-BLE discovery running.
- Added cautious, bidirectional Classic/BLE identity correlation based on exact
  normalized names, compatible advertised/SDP profiles, temporal overlap, and
  RSSI proximity. Related identifiers remain separate and are labeled
  probable with medium/high confidence and supporting evidence.
- Bluetooth scan export now includes bounded raw HCI command, event, and ACL
  traffic as an owner-private Wireshark-readable `.btsnoop` file.
- Added an **Enterprise EAP lab honeypot** for authorized lab and engagement
  testing. From AP Focus → **Enterprise** (`E`) → **Start PEAP EAP lab
  honeypot**, a spoof-capable radio advertises a locally administered twin BSSID
  with the target ESSID and a **full cloned beacon** (same IE fingerprint as the
  real AP, with RSN rewritten to a single 802.1X AKM and SAE/RSNXE stripped),
  then terminates outer **PEAP**, **EAP-TTLS**, or **EAP-TLS** with an ephemeral
  OpenSSL-generated lab certificate under the private data directory.
- The lab server captures inner **MS-CHAPv2** challenge/response material for
  PEAP and TTLS tunnels. Each capture is written to Vault as paired Hashcat
  lines: `*_mschapv2.mschapv2` (mode **5500**) and `*_netntlmv2.netntlmv2`
  (mode **5600** NetNTLMv2-SSP). Vault Hashcat launch selects the mode from
  the file extension (22000, 5500, and 5600).
- Optional **deauthentication, CSA, and BTM** eviction bursts toward the real AP
  (respecting PMF) can run on a fixed interval to encourage clients to attach
  to the lab twin. Eviction is configurable in the launch modal and uses the
  same bounded punt machinery as other active campaigns.
- **EAP-TLS** can request a client certificate (`CERT_OPTIONAL`). When a client
  presents one, the lab logs the SHA-256 fingerprint only; private keys and
  certificate payloads are not stored.
- Added `EapLabModal` launch options (duration, eviction, client-cert request),
  Enterprise panel integration, Vault indexing for MS-CHAPv2 and NetNTLMv2
  artifacts, capture-history typing, and tests for MS-CHAPv2 parsing, PEAP/TTLS
  server behaviour, persistence, and Hashcat mode mapping.
- Added **Enterprise client misconfiguration assessment** to the EAP lab: weak
  outer EAP ordering, inner **PAP** probe, empty MS-CHAPv2 detection, untrusted
  EAP-TLS Success findings, isolated **lab DHCP Offer/ACK** (`10.99.0.0/24`), and
  automatic Vault **`_eap_lab_report.json`** snapshots with pseudonymized client
  IDs and structured outcomes.
- Added optional cross-platform **NMEA USB GPS** support through `pyserial`.
  Startup enumerates serial ports on Linux, macOS, and Windows, prioritizes
  likely GNSS/Prolific devices, verifies checksummed NMEA sentences, and tries
  common GNSS baud rates automatically instead of identifying a receiver from
  a generic USB-to-serial VID/PID alone. A toast reports the detected port and
  baud rate; missing `pyserial` now produces a warning instead of preventing
  application startup.
- Added GPS Preferences for a manual serial port (blank keeps automatic
  detection) and portable-device movement distance, with a 20-metre default
  and minimum. A separate required-accuracy preference sets the maximum
  accepted GPS error radius and defaults to 20 metres. Changing the port
  reconfigures the background GPS reader without restarting the application.
- Added owner-private `location_history.sqlite3` persistence. Observed Wi-Fi
  APs retain the valid GPS position associated with their strongest RSSI;
  locally created evil-twin and probe-test APs record the current valid fix
  when the test starts. Stale, invalid, no-fix, and fixes worse than the
  configured accuracy requirement are rejected.
- Wi-Fi stations and Bluetooth/BT/BLE devices retain multiple position
  clusters when observations move beyond the configured distance. Each
  cluster keeps its strongest-RSSI position, using better GPS accuracy to
  break equal-RSSI ties. Position lookups are cached in memory so high-rate
  wireless observations do not perform a SQLite read per packet.
- Added position evidence to Wi-Fi JSON/CSV and Bluetooth CSV/JSON/JSONL scan
  exports. Coordinates are explicitly the receiver's position at observation
  time, not proof of a transmitter's exact location; rotating BLE identifiers
  can retain separate histories.
- Expanded `Ctrl+D` diagnostics with a live GPS section showing serial port,
  detected baud, coordinates, satellite count, estimated accuracy, fix age,
  and `SEARCHING`, `NO FIX`, `LOW ACCURACY`, `FIX`, `STALE`, or `UNAVAILABLE`
  state. A clickable Google Maps link is enabled only when coordinates exist
  and sends that coordinate to Google only when clicked.

### Changed

- Hardened RTL8761BU startup by distinguishing the known stock ROM from the
  bundled patched identity, rejecting unknown controller revisions, and
  confirming that the expected firmware identity is active after upload.
- Added the upstream ASUS RTL8761BU USB ID `0b05:190e`.
- Expanded the README compatibility table with documented RTL8761BU/BUV
  adapters from ASUS, TP-Link, UGREEN, EDUP, Edimax, Delock, and Sandberg,
  while retaining USB-ID and runtime-identity checks for revision changes.
- BLE GATT timeouts now show an actionable explanation. When the selected row
  also has Classic evidence, scanning resumes and the app opens read-only
  Classic Focus automatically instead of displaying a raw `TimeoutError`.
- Bluetooth and BLE rows now use the same configurable inactivity expiry as
  Wi-Fi, including **Never**; the Preferences label names both media.
- A dedicated-controller claim failure now displays a red bottom notification
  asking for the Sena UD100 by name, or a generic Bluetooth USB device, to be
  unplugged and re-plugged so wifit3 can claim it from the OS.
- Split Bluetooth diagnostics into separate **BLE** and **Classic Bluetooth**
  rows with per-radio device counts, observation totals, activity age,
  backend, GATT reads, and scanner health.
- Updated Enterprise documentation and UI copy: the assessment suite still
  performs passive/active **outer** EAP analysis only for normal probes, while
  the separate EAP lab honeypot is an explicit, confirmed active action for
  inner MS-CHAPv2 capture and client hardening tests where policy allows.

## 0.3.7 - 2026-09-28

### Added

- Added a private, versioned SQLite AP knowledge store keyed by BSSID. A live
  AP observed in a later session is enriched automatically with its confirmed
  SSID, country, security/RSN posture, radio capabilities, WPS state,
  Enterprise observations, same-radio relationships, and source-preserving
  OUI/WSC Beacon/WSC M1 identity evidence.
- Historical data only fills missing fields; current packet evidence remains
  authoritative. Saved APs never create phantom scanner rows and only appear
  after their BSSID is observed live.
- Added ordered schema migrations, foreign-key enforcement, WAL operation,
  secure deletion, bounded retention of the 20,000 most recently seen APs,
  debounced updates, serialized cross-thread access for receive callbacks, and
  owner-private database/directory permissions.
- New SQLite stores start empty. There is deliberately no automatic migration
  from legacy JSON/JSONL or historical PCAP analysis; old files are left
  untouched and ignored.
- Added a separate private, versioned, bounded Bluetooth/BT/BLE SQLite history.
  A device observed live again can recover its prior name, service UUIDs,
  manufacturer IDs, radio modes, transmit power, and class-of-device data.
  Historical devices never create scanner rows on their own, and live values
  take precedence.
- Added evidence-backed Bluetooth device classification. BLE GAP Appearance,
  Bluetooth Classic Class-of-Device major/minor values, and standard Classic/LE
  service profiles take precedence over low-confidence name hints. Scanner
  Focus and exports report the exact inferred type, broad category, evidence
  source, confidence, and ambiguous conflicts instead of presenting a guessed
  label as fact.
- Added GAP Appearance parsing to direct USB HCI advertisements and guarded
  Linux BlueZ metadata extraction for `Appearance`, `Class`, and `AddressType`.
  Bluetooth history schema v6 persists Appearance plus a structured snapshot
  of classification, evidence source, confidence, ambiguity, signal window,
  advertisement activity, baseline state, discovery source, and fingerprints;
  normalized advertising-protocol evidence is retained separately so later
  observations can recover it. Existing databases migrate in place.
- Bluetooth history updates are now debounced per identifier regardless of
  changing RSSI or payload fingerprints, preventing high-rate advertisers from
  causing one SQLite transaction per packet.
- Expanded classification for earbuds, headsets, headphones, speakers,
  keyboards, mice, game controllers, smartwatches, computers, phones, toys,
  health sensors, network devices, displays, appliances, vehicles, and other
  assigned Appearance and Classic Class-of-Device categories. The Classic
  decoder now covers computer, phone, wearable, toy, and health minors and
  correctly consumes all four peripheral-subclass bits.
- Added a compact, auditable Bluetooth signature catalog based on Bluetooth
  SIG Assigned Numbers, BlueZ profile constants, and stable identifiers
  cross-checked against Home Assistant's Apache-2.0 matcher database. It adds
  current Classic SDP and BLE GATT services without importing broad device-name
  guesses or treating a protocol as proof of an unsupported physical subtype.
- Added exact manufacturer-frame signatures from the MIT-licensed reelyActive
  advlib database for supported Efento, EnOcean, Wiliot, Code Blue, Minew,
  ELA Innovation, HibouAir, Laird, MOKO/MOKOSmart, and Espruino devices.
  Selected MIT-licensed AirHound composite signatures add Raven acoustic
  sensors, Find My-compatible trackers, and Flock devices. Weak OUI-only and
  unscoped byte signatures are deliberately rejected.
- Linux BlueZ discovery now consumes a validated Device ID `Modalias` and
  resolves it against the local systemd hardware database with a bounded,
  cached, shell-free query. Resolved vendor/product identity is searchable,
  displayed in Focus, included in exports and classification evidence, and
  retained by Bluetooth history schema v7. GPLv3 Theengs and CC-BY-SA 4.0
  CLUES data remain documented research references rather than being copied
  into this GPL-2.0-only distribution.
- Added bounded parsing of verified advertising identifiers for Apple iBeacon,
  Apple Proximity Pairing audio and HomeKit, Google Fast Pair, Eddystone,
  AltBeacon, BTHome, Ruuvi sensor formats 3/5, Xiaomi MiBeacon, Tile, Estimote,
  Nordic Secure DFU/UART, SwitchBot, Airthings, Aranet, Find My, and Exposure
  Notification. Manufacturer-only observations now display a low-confidence
  vendor-specific device label instead of an unhelpful `Unknown`/`Other`,
  without guessing a subtype that was not advertised.
- Widened the Bluetooth scanner `RADIO / TYPE` column so evidence-backed exact
  types remain visible instead of being truncated to the old broad-category
  width.
- Bluetooth scan export now writes owner-private CSV, structured JSON, and
  streaming-friendly JSONL snapshots with address type, Appearance,
  Class-of-Device, exact and broad type, evidence source, confidence, baseline
  state, signal trends, and privacy-safe fingerprints.
- Added `C · Clear-DB` to the startup device-selection footer as the only
  database-deletion action.
  Wi-Fi and Bluetooth/BLE histories can be selected independently or together,
  and deletion remains disabled until the user types exactly `DELETE NOW!`.
  Wi-Fi deletion includes AP knowledge, hidden SSIDs, directed probes,
  association profiles, Enterprise sessions, network metadata, and Wi-Fi
  targets. Bluetooth deletion includes device history, advertisement/GATT
  events, and Bluetooth targets. PCAPs, keys, reports, and scan exports remain.
- Added persistence and integration tests for schema creation,
  private permissions, live-over-history precedence,
  source-level identity restoration, sibling relationships, startup AP
  enrichment, immediate WSC M1 writes, clearing, and malformed input.
- Added bidirectional AP↔client association history to the private AP database.
  Exact association/data evidence records first and last observation times and
  can be queried from either the AP BSSID or client MAC without creating
  phantom AP scanner rows.
- AP Focus now merges current stations with prior associated clients and
  clients that directed probes at the AP's SSID. Historical entries use a
  soft-grey `◌` row, explain whether the evidence was an association or probe,
  cannot be deauthenticated, and do not activate the live client connector.
- The Wi-Fi client table and Client Focus now show previously used APs in grey.
  Persisted probe requests are grey until seen live again. Probe history is
  still treated as SSID-only evidence and never promoted to an exact BSSID
  association.
- Restricted directed-probe persistence to globally assigned unicast STA MACs
  with a manufacturer-resolved OUI. Randomized, locally administered, and
  unknown-OUI probes remain available during the live session but are not
  written to SQLite. Existing non-manufacturer probe rows are pruned when the
  private history opens; confirmed AP associations remain persistent
  regardless of client MAC randomization.
- The automated probe honeypot can now advertise an OPEN and a WPA2-PSK BSSID
  at the same time (`OPEN + WPA2` in the security selector). Radios are assigned
  automatically: when two spoof-capable cards can reach the channel each BSSID
  gets its own radio (and its own hardware ACK), otherwise both BSSIDs share one
  card, where the second BSSID responds best-effort in software. Each BSSID is
  registered and tracked independently, and WPA2 M2 material is saved to Vault
  per BSSID.
- Added an **Enterprise** choice to the scanner's upper encryption filter. It
  selects APs advertising EAP/802.1X authentication, including FT-EAP,
  EAP-SHA256, Suite-B, Suite-B-192, and FT-EAP-SHA384. Personal PSK/SAE, OWE,
  OPEN, and WEP networks are excluded; mixed PSK+EAP APs remain included
  because they advertise an Enterprise authentication path.

#### WPA-Enterprise assessment suite

- Added an Enterprise assessment panel to AP Focus with an `E` shortcut. It
  explains observed methods, TLS and certificate evidence, findings,
  confidence, coverage, remaining unknowns, persisted sessions, probe history,
  and per-phase timelines.
- Added infrastructure correlation across same-SSID Enterprise BSSIDs and
  systems sharing certificate fingerprints. The panel compares channels,
  method consistency, PMF posture, shared certificates, and RADIUS leaf
  certificate variance.
- Extended passive EAP analysis with server/client method separation, legacy
  NAK alternatives, Success/Failure counters, and passive/active evidence
  sources.
- Added bounded TLS ClientHello parsing for offered versions and ciphers, SNI,
  supported groups, and signature algorithms.
- Extended X.509 parsing with subject, issuer, DNS SAN, EKU, CA status, and
  ordered chain metadata in addition to fingerprints, validity, signatures,
  key algorithms, and key sizes.
- Added structural certificate findings for short EC keys, missing
  `serverAuth`, a CA-marked leaf, missing DNS SAN, incomplete chains, and
  issuer/subject mismatches.
- Added private, bounded, versioned, atomic Enterprise session persistence.
  Client MAC addresses use per-store HMAC pseudonyms; EAP identities,
  credential responses, and packet payloads are not persisted.
- Added a confirmed, cancellable active outer-EAP probe. It associates with a
  randomized station, sends an anonymous outer identity, uses EAP NAK method
  negotiation, and supports bounded outer TLS for EAP-TLS, EAP-TTLS, PEAP, and
  TEAP.
- Added EAP-TLS fragmentation and acknowledgement handling, duplicate-request
  retransmission, declared-length checks, lower-flag preservation, TLS 1.2+
  enforcement, and a 1 MiB reassembly ceiling.
- The active probe stops before inner authentication and sends no password,
  MSCHAPv2 response, private key, or client certificate.
- Added sanitized Enterprise JSON reports to Vault with schema validation, an
  `ENTERPRISE` tab, `✓ENT` badge, manual save action, archive inclusion, and
  automatic snapshots after completed, partial, failed, or cancelled probes.
- Added tests for Enterprise protocol parsing, persistence, certificate
  findings, infrastructure correlation, active probing, reports, Vault
  integration, and private file modes.

### Changed

- Migrated saved targets, hidden SSIDs/directed probes, Enterprise sessions,
  open-network metadata, and Bluetooth target events from JSON/JSONL files to
  private SQLite databases. Legacy files are not read, changed, or deleted
  automatically.
- Bluetooth event capture now writes bounded advertisement and GATT records
  directly to SQLite. The existing size/part preferences become an equivalent
  total byte ceiling; unlimited mode remains available.
- Moved **Fake-Connect** out of the Focus footer menu and made it an
  upper action-bar button, matching **EvilTwin**. The button is shown only for
  eligible OPEN and WEP APs and changes to **Disconnect** while the temporary
  client is connected.
- Removed the redundant **AP MFR** scanner column. **VENDOR/ID** remains as the
  single AP identity column because it already combines the IEEE OUI vendor
  with higher-quality WSC manufacturer, model, and device information.
- Hardened local persistence: sensitive files use owner-only `0600` modes and
  private directories use `0700` where POSIX permissions are available. This
  covers credentials, Hashcat material, PCAP, Enterprise reports and sessions,
  scan exports, WPS state, Vault job state, configuration stores, and capture
  archives.

### Fixed

- Preserved the selected client MAC when another client row disappears immediately
  before a live re-sort. The selection is restored after Textual applies the row
  removal, preventing the highlight from silently moving to the adjacent client.
- A card claimed for a fixed-channel campaign (honeypot, Evil Twin, WPS PBC) is
  now excluded from every hop partition, so a mid-campaign re-hop (a hotplug
  re-partition, the device watcher, or a single-card pool) can no longer tune it
  off its channel. Previously a single-card honeypot could keep channel-hopping.
- The honeypot now keeps a strong reference to in-flight response frames and
  drains them on teardown, so no auth/assoc/probe/M1 frame is dropped by the GC
  or transmitted after the radio lease is restored.
- Clients that engage the honeypot (auth/assoc/M2/DHCP) are always recorded even
  on a busy channel; the observed-client cap now bounds only passive scanners.
- Prior scan exports of our own synthetic honeypot APs are no longer reloaded as
  RSN cloning evidence.
- Preserved observed TLS certificate order across Enterprise persistence so
  leaf-to-root structural chain checks do not produce fingerprint-sort
  mismatches.

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
