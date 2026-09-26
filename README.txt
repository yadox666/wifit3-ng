WIFIT3 ENHANCED LOCAL BUILD
===========================

This tree is an expanded, unofficial build based on the original wifit3
project at https://github.com/derv82/wifit3.

The upstream introduction, installation instructions, supported hardware,
license, and acknowledgements remain in README.md. This file documents the
additional functionality implemented in this build.


MAIN NAVIGATION
---------------

- The startup screen presents centered Wi-Fi and Bluetooth/BLE buttons on one
  line. Press W for Wi-Fi or B for Bluetooth.
- U updates the IEEE OUI manufacturer database from the startup screen.
- Ctrl+P opens Preferences.
- Ctrl+D opens active-adapter diagnostics.
- Ctrl+Q exits from every screen.
- Escape returns from Wi-Fi and Bluetooth screens to the previous selection
  screen where appropriate.
- About and the target editor are available from Preferences.
- Vault is intentionally available only in Wi-Fi mode.


WI-FI SCANNER
-------------

- Switch between AP and client tables with T.
- Both tables use consistent signal colours, fixed columns, sorting, reverse
  sorting, filtering, pause, channel lock, and CSV/JSON export.
- AP rows include manufacturer, client-manufacturer summary, security, WPS,
  identity, channel, signal, beacon activity, client count, and last-seen /
  expiry information.
- Client rows include associated AP, manufacturer, signal, packets, age, and
  probe requests.
- AP expiry is configurable in Preferences, including a Never option.
- Manufacturer names are resolved through the local OUI database.
- The OUI database can be refreshed manually and is refreshed at most once per
  month when its update policy requires it.
- Exact saved targets are visibly marked with a red ! indicator even when
  automatic locking is disabled.


SSID INFRASTRUCTURES
--------------------

- Two or more visible APs advertising the same confirmed SSID are collapsed
  into one infrastructure row by default.
- The row aggregates AP count, channels, strongest signal, beacon count,
  clients, manufacturers, WPS availability, and security.
- Press Enter on a collapsed infrastructure to expand it.
- Press I on a grouped AP to expand or collapse its infrastructure.
- Expanded APs remain individually selectable for Focus, capture, and targets.
- SSIDs recovered only from historical data are not grouped until reconfirmed.
- A shared SSID is evidence of a common ESS name, not proof that every AP has
  the same owner.


AP AND CLIENT INFORMATION
-------------------------

- AP Focus shows uptime, advertised country, radio modes, channel widths,
  spatial streams, rates, BSS load, timing, power constraints, RSN ciphers,
  AKMs, PMF, roaming features, vendor IEs, WPS identity, and device identity.
- Client information includes manufacturer, randomized/local MAC status,
  association, selected AKM, PMF, radio capabilities, limits, probe requests,
  and observed Enterprise authentication.
- WPS Info remains available from the AP Focus key menu and magnifying-glass
  control.
- Entering normal AP Focus fixes the scanner to the AP channel until Focus is
  left.
- Signal colours are consistent across AP, client, and Bluetooth views.


PASSIVE WPA-ENTERPRISE ANALYSIS
-------------------------------

- Parses visible non-key EAPOL/EAP exchanges without retaining EAP Identity
  values or credential-response payloads in the profile.
- Recognises Identity, EAP-MD5, EAP-TLS, LEAP, EAP-TTLS, PEAP,
  EAP-MSCHAPv2, EAP-FAST, EAP-AKA', and TEAP.
- Performs bounded reassembly of fragmented outer EAP-TLS data.
- Extracts visible TLS versions, selected cipher suites, certificate
  fingerprints, validity dates, signature algorithms, key algorithms, and key
  sizes.
- Detects and explains risks including WEP, legacy WPA, TKIP, missing or
  optional PMF, EAP-MD5, LEAP, direct EAP-MSCHAPv2, obsolete TLS, weak TLS
  ciphers, expired certificates, MD5/SHA-1 signatures, and short RSA keys.
- Findings include evidence and confidence. High-risk observations add a
  !WEAK marker to the AP table and a security warning in Focus.
- PEAP/TTLS inner methods and client RADIUS-certificate validation are
  encrypted and cannot be determined by passive scanning.
- No automated rogue-RADIUS or credential-validation attack is included.


PACKET CAPTURE AND VAULT
------------------------

- Press X in AP Focus to start or stop a focused libpcap capture.
- A locked AP target starts capture automatically after the channel-tuning
  attempt.
- A locked associated client opens Client Focus and automatically captures
  frames involving that client on its AP channel.
- AP captures include both AP-to-client FromDS and client-to-AP ToDS traffic
  whose parsed BSSID matches the focused AP.
- PCAP files use standard IEEE 802.11 libpcap format and are indexed in the
  Vault under the PCAP category.
- Captures rotate at the configured size and stop at the configured part limit.
- AP and client Focus show a blinking red "PCAP RECORDING" indicator.
- Capture filenames follow the Vault naming and sorting convention.


TARGETS
-------

- Press N on a selected Wi-Fi AP, Wi-Fi client, or exact Bluetooth device to
  create a target.
- The New Target dialog shows known details and provides Save & Continue,
  Save & Lock, and Cancel actions.
- Targets have aliases and can contain Wi-Fi APs, Wi-Fi clients, and Bluetooth
  devices in one private targets.json file.
- Existing targets fill previously empty details when observed again.
- Auto-lock saved targets is optional and disabled by default.
- The first eligible observed target can be locked automatically.
- A manual lock replaces the active lock.
- Associated Wi-Fi clients open a dedicated Client Focus screen.
- Unassociated clients wait until an association is observed; no channel is
  guessed.
- Target locks time out when the device cannot be reacquired.
- Preferences > Targets supports rename, enable/disable, priority ordering,
  and deletion.


BLUETOOTH / BLE
---------------

- Bluetooth has a dedicated scanner, filters, stable columns, activity
  counters, signal colours, sorting, reverse sorting, and CSV export.
- Anonymous Apple privacy identifiers can be shown as a clearly marked
  approximate group and expanded without claiming that rotating identifiers
  prove a single physical identity.
- Exact Bluetooth devices can be connected in read-only mode without pairing.
- Bluetooth Focus shows identity, manufacturer, likely category, services,
  characteristics, values, notifications, traffic, and exposure findings.
- Bluetooth diagnostics report the active system adapter and scanner health.
- Locked Bluetooth targets reconnect within the configured reacquisition
  timeout.
- Bleak does not provide raw BLE link-layer packets, so locked Bluetooth
  targets record advertisements and read-only GATT observations as rotating
  JSONL files instead of fake PCAP files.
- Bluetooth Focus shows a blinking red "BLE EVENT RECORDING" indicator.


HIDDEN SSID HISTORY
-------------------

- When a network first appears hidden and its SSID is later revealed, the
  BSSID-to-SSID relationship is stored in private hidden_ssids.json.
- A later hidden observation of that exact BSSID is automatically labelled
  with the historical SSID.
- Historical, unconfirmed names are yellow and end in ? until observed again.
- Records include reveal method and first/last reveal timestamps.


PREFERENCES AND DIAGNOSTICS
---------------------------

Preferences include:

- Theme.
- Scanner sort delay.
- Inactive-AP display lifetime.
- Active-action intensity.
- Capture directory.
- Automatic update checks.
- Confirmation for active wireless actions.
- Automatic WPS PBC capture.
- Automatic saved-target locking.
- Target reacquisition timeout.
- Capture rotation size and part limit.
- Handshake PCAP saving.

Automatic update checking performs one HTTPS request at startup to the
yadox666/wifit3 GitHub latest-release API. It reports an available release but
never downloads or installs it. Scan and device data are not sent.


PRIVATE LOCAL FILES
-------------------

- targets.json: aliases and observed target metadata.
- hidden_ssids.json: historical BSSID-to-SSID mappings.
- target_events*.jsonl: Bluetooth target observations.
- captures/: handshakes, focused PCAP files, exports, and Bluetooth events.

These paths are excluded by .gitignore. Configuration JSON files are written
in the operating system's wifit3 user-configuration directory with private
file permissions where supported.


SECURITY AND PRIVACY
--------------------

- Use this software only on equipment and networks you own or are explicitly
  authorised to audit.
- PCAP and JSONL files can contain sensitive traffic, identifiers, EAP
  identities, service values, and network metadata. Protect the capture
  directory and do not publish it.
- Approximate Bluetooth groups and same-SSID Wi-Fi groups are presentation
  aids, not proof of physical identity or ownership.
- Passive Enterprise findings describe observed evidence only. They cannot
  prove the security of encrypted inner authentication or client certificate
  validation.


VALIDATION
----------

The enhanced build is covered by the upstream suite plus additional tests for
Bluetooth, targets, PCAP rotation, hidden SSID history, infrastructure
grouping, and passive Enterprise analysis.
