# wifit3 - Enhanced Fork
> A standalone USB Wi-Fi and Bluetooth auditor for Linux, Windows, and macOS.

This repository is an enhanced fork of the original
[derv82/wifit3](https://github.com/derv82/wifit3), upgraded and maintained by
[Yadox (@yadox666)](https://github.com/yadox666).

The excellent original development by
[derv82](https://github.com/derv82) made this fork possible. Its direct
user-space USB mini-drivers, cross-platform wireless stack, scanner, capture
engines, and auditing workflows remain the technical foundation of the
project. This fork preserves that work while expanding reconnaissance,
analysis, capture, target tracking, Bluetooth/BLE support, and the terminal
interface.

See [Enhanced Fork Features](#enhanced-fork-features) below and
[CHANGELOG.md](CHANGELOG.md) for the detailed changes from the original
project.

<p align="center">
  <img src="assets/wifit3-1-splash.png" alt="wifit3 splash / adapter picker" width="700">
</p>

> *At least* one of the [supported USB adapters](#supported-hardware) is **required**.

## Why?
* **Cross-Platform:** Runs identically on Linux, macOS, and Windows.
* **Wireless Driver Heaven:** Built-in wireless stack avoids kernel driver versioning hell and Windows' NDIS.
* **Zero Runtime Dependencies:** No `aircrack-ng` or `reaver`, just pure Python with PyUSB & Textual libraries.

<p align="center">
  <img src="assets/wifit3-demo.gif" alt="wifit3 in action: WPS PushButton PSK capture" width="700">
</p>

---

## Features

### Reconnaissance & Analysis
- **Multi-Card Aggregation:** Capture packets across multiple adapters simultaneously; pick a dedicated card to inject.
- **Real-time Scanner:** 2.4GHz & 5GHz channel-hopping (split for multi-cards); tracks signal strength, encryption suites, WPA3/SAE transition modes.
- **AP & Client Identification:** Fingerprints device vendors and categories; extracts router make and model from WPS beacons.
- **VAP Decloaking:** Identifies hidden networks by correlating their BSSIDs with known visible siblings.
- **Packet Dashboard:** Visualizes real-time beacon, data, injection, and deauthentication packet rates.

### Attacks & Captures
- **WPA/WPA2 Handshakes:** Passive sniffing and targeted deauthentication; validates crackable pairs; exports `.pcap` and `.hc22000` files.
- **PMKID Harvesting:** Active association harvest and passive sniffing for WPA/WPA2 PMKID key material (`.hc22000`).
- **EvilTwin WPA3 Downgrade:** Clones the AP and evicts clients (via CSA, BTM, and de-auths) to capture handshakes. Works on single and multiple cards.
- **WPS Recovery Suite:**
  - **PixieDust (2 Modes):** Instant offline PIN recovery exploiting *Null Secret* and *Static Secret* PRNG weaknesses.
  - **PushButton (PBC):** Detects physical WPS button presses and immediately extracts the plaintext WPA PSK.
  - **PIN Brute-Force:** Resumable WPS PIN cracking with known-PIN database and AP lock monitoring.
- **WEP Suite:** Pure Python ARP replay, ChopChop, Fake Authentication, and PTW key recovery.

## Enhanced Fork Features

### Wi-Fi Discovery and Presentation

- Switchable AP and client scanner views with stable columns, pause, filters,
  sorting, reverse sorting, channel lock, and CSV/JSON export.
- Consistent signal colours across AP, client, and Bluetooth views.
- AP manufacturer and client-manufacturer identification using a local IEEE
  OUI database, with manual updates and an automatic monthly refresh policy.
- Detailed client rows with associated AP, manufacturer, signal, packet
  activity, last-seen age, and probe requests.
- Configurable inactive-AP display lifetime, including a `Never` option.
- Saved targets are marked with a red `!` even when automatic locking is
  disabled.

### Infrastructure and Identity Analysis

- APs advertising the same confirmed SSID can be collapsed into an
  infrastructure and expanded to inspect each BSSID individually.
- Infrastructure rows summarize AP count, channels, strongest signal,
  beacons, clients, manufacturers, security, and WPS availability.
- Hidden SSIDs revealed during scanning are remembered by exact BSSID and
  restored on later observations. Historical names remain visibly marked
  until reconfirmed.
- AP Focus displays uptime, advertised country, radio modes, channel widths,
  spatial streams, rates, BSS load, timing, power constraints, RSN ciphers,
  AKMs, PMF, roaming support, vendor IEs, WPS information, and device
  identity.
- Client details include manufacturer, randomized/local MAC status,
  association, selected AKM, PMF, radio capabilities, limits, probes, and
  observed Enterprise authentication.

### Passive WPA-Enterprise Assessment

- Recognizes visible EAP Identity, EAP-MD5, EAP-TLS, LEAP, EAP-TTLS, PEAP,
  EAP-MSCHAPv2, EAP-FAST, EAP-AKA', and TEAP exchanges.
- Reassembles bounded outer EAP-TLS fragments and inspects visible TLS
  versions, cipher suites, certificate fingerprints, validity periods,
  signature algorithms, key algorithms, and key sizes.
- Reports evidence and confidence for WEP, legacy WPA, TKIP, weak PMF,
  EAP-MD5, LEAP, direct EAP-MSCHAPv2, obsolete TLS, weak ciphers, invalid
  certificate dates, weak signatures, and short RSA keys.
- High-risk observations display a `!WEAK` scanner marker and an explanation
  in Focus.
- EAP Identity values and credential-response bodies are not retained in the
  Enterprise profile. Encrypted inner EAP methods and client certificate
  validation cannot be determined passively.

### Targets, Focused Capture, and Vault

- Wi-Fi APs, Wi-Fi clients, and exact Bluetooth devices can be saved together
  as named targets.
- The New Target dialog supports Save & Continue, Save & Lock, and Cancel;
  the Preferences target editor supports rename, enable/disable, priority
  ordering, and deletion.
- Optional auto-lock selects the first eligible saved target. A manual lock
  replaces it, and observed data fills previously empty target fields.
- Associated client targets open a dedicated Client Focus view. Unassociated
  clients wait for an observed association instead of guessing a channel.
- Locked Wi-Fi targets tune to the related channel and start standard IEEE
  802.11 libpcap capture automatically.
- AP capture retains both AP-to-client and client-to-AP traffic for the
  focused BSSID; client capture filters for the exact station.
- Captures rotate at configurable size and part limits, appear in Vault, and
  display a blinking red `PCAP RECORDING` indicator in AP or Client Focus.

### Bluetooth and BLE

- Dedicated Bluetooth/BLE scanner with fixed identity and activity columns,
  signal colours, filters, sorting, reverse sorting, and CSV export.
- Displays manufacturer, likely device category, services, advertisement
  activity, intervals, identifiers, first-seen time, and last-seen age.
- Anonymous Apple privacy identifiers may be shown as an explicitly
  approximate, expandable group without claiming they are the same physical
  device.
- Read-only, no-pairing Bluetooth Focus inspects services,
  characteristics, values, notifications, traffic, and exposure findings.
- Active-adapter diagnostics report scanner and system-adapter health.
- Exact saved Bluetooth targets can auto-connect in read-only mode and
  reconnect during the configured reacquisition period.
- Because Bleak does not expose raw BLE link-layer packets, Bluetooth target
  capture records rotating JSONL advertisement and GATT evidence instead of
  creating misleading PCAP files. Focus displays a blinking red
  `BLE EVENT RECORDING` indicator.

### Navigation, Preferences, and Local Data

- The startup screen provides centered Wi-Fi and Bluetooth/BLE choices with
  highlighted `w` and `b` shortcuts and a manual OUI update action.
- `Ctrl+P` opens Preferences, `Ctrl+D` opens adapter diagnostics, `Ctrl+Q`
  exits globally, and `Escape` returns to device selection where appropriate.
- Preferences include theme, scanner delay, AP expiry, active-action
  confirmation and intensity, update checks, WPS PBC automation, target
  auto-lock and reacquisition, capture location and rotation, and handshake
  PCAP saving.
- Vault remains Wi-Fi-specific. Bluetooth observations use their own JSONL
  event records.
- Target data, hidden-SSID history, captures, Bluetooth events, and scan
  exports are excluded from Git. Protect these files because captures may
  contain sensitive network and device metadata.
- Automatic update checking only queries this fork's
  `yadox666/wifit3` GitHub latest-release API. It reports updates but never
  downloads or installs them.

## Screenshots

| Scanner | Focus (single target) |
|---|---|
| ![Scanner](assets/wifit3-2-scanner.png) | ![Focus](assets/wifit3-3-focus-handshake.png) |

## Supported Hardware

> **Important:** *At least one supported USB wireless adapter is required.*

| Chipset | Bands | Cards (Make + Model) |
|---|---|---|
| Atheros AR9271 | 2.4 GHz | ALFA AWUS036**NHA**, TP-Link TL-WN722N V1 |
| MediaTek MT7610U | 2.4 / 5 GHz | ALFA AWUS036**ACHM**, Panda PAU0B |
| MediaTek MT7612U | 2.4 / 5 GHz | ALFA AWUS036**ACM** |
| MediaTek MT7921AU | 2.4 / 5 GHz | ALFA AWUS036**AXML**, Panda PAU0F |
| MediaTek MT7925U | 2.4 / 5 GHz | Netgear A9000 |
| Realtek RTL8812AU | 2.4 / 5 GHz | ALFA AWUS036**ACH** |
| Realtek RTL8814AU | 2.4 / 5 GHz | ALFA AWUS1900 |
| Realtek RTL8821AU | 2.4 / 5 GHz | ALFA AWUS036**ACS**, TP-Link Archer T2U Plus/Nano |
| Realtek RTL8821CU | 2.4 / 5 GHz | Auscoumer 600 Mbps |
| Realtek RTL8922AU | 2.4 / 5 GHz | ASUS USB-BE93 |
| Realtek RTL8822BU | 2.4 / 5 GHz | TP-Link T3U Plus, Archer T4U v3 / T4U+ |
| Realtek RTL8822CU | 2.4 / 5 GHz | D-Link AC13U |
| Realtek RTL8187L | 2.4 GHz | ALFA AWUS036**H** |
| Realtek RTL8188EUS | 2.4 GHz | TP-Link TL-WN722N v2/v3 |
| Ralink RT2570 | 2.4 GHz | Buffalo Nintendo Wi-Fi USB Controller |
| Ralink RT3070 | 2.4 GHz | ALFA AWUS036**NH** |
| Ralink RT5370 | 2.4 GHz | LOTEKOO 150 Mbps |
| Ralink RT5372 | 2.4 GHz | Panda PAU05/PAU06 |
| Ralink RT5572 | 2.4 / 5 GHz | Panda PAU09 N600 |

Breakdown of each device's capabilities and limitations: [Supported Hardware Doc](docs/SUPPORTED-HARDWARE.md).

## Installation & Running

### Option 1: Download Prebuilt Fork Binaries
Download the latest standalone executable from the
[enhanced fork releases](https://github.com/yadox666/wifit3/releases/latest).

* **Windows:** Download and run `wifit3-windows-x64.exe`.
* **Linux (non-sudo):** `chmod +x wifit3-linux-x64 && ./wifit3-linux-x64`
* **macOS:** (bypass quarantine)
  ```bash
  xattr -d com.apple.quarantine wifit3-macos-universal2
  chmod +x wifit3-macos-universal2
  ./wifit3-macos-universal2
  ```

### Option 2: Run from Source
wifit3 uses Astral's [`uv`](https://docs.astral.sh/uv/). `sync` sets up dependencies:
```bash
uv sync
uv run wifit3
```

### Option 3: Build your own binary
```bash
uv run pyinstaller wifit3.spec --noconfirm --clean
```
Binary executable is written to `dist/` subdirectory.

## One-Time Driver Setup

wifit3 automatically handles hardware configuration within the app, after clicking the `START` button:

- **Linux:** Prompts once via `pkexec`/`sudo` to write udev permissions and blocklists in `/etc/modprobe.d/`.
- **macOS:** No installation required; plug in the device and select *Allow* in the authorization dialog.
- **Windows:** Prompts once via UAC to install WinUSB for the device.

## Uninstalling
Return the previously-installed device to your operating system's Wi-Fi stack:

1. Select the card on the wifit3 splash screen.
2. Click the `Uninstall` button and confirm.
3. Accept the elevation prompt (UAC on Windows or `pkexec` on Linux).
4. Unplug and re-plug the adapter.

On Linux, this deletes wifit3's `udev` and `modprobe` rules.
On Windows, this uninstalls the WinUSB binding, and triggers a PnP device rescan (old driver reattaches).

## *Thank you, Linux!*

wifit3 only exists because of the great people who reverse-engineered and maintained these Linux wireless
drivers. It's usually a thankless job.

Special thanks to:
- **Christian "kimo" B. ([@kimocoder](https://github.com/kimocoder))** who maintains **wifite2** and `aircrack-ng`'s RTL8188EUS DKMS driver.
- [**Neur0sp1cy**](https://github.com/neur0sp1cy): Close friend and the master to my Linux & wireless-hacking apprenticeship.
- **Nick Morrow** ([@morrownr](https://github.com/morrownr)), legend, maintains the out-of-tree Realtek USB
  DKMS drivers.

The full list is in **[CREDITS.md](docs/CREDITS.md)**.

## How it Works: Mini-Drivers

wifit3 bypasses the operating system's native Wi-Fi stack entirely. It ships with lightweight Python ports of Linux kernel drivers ([src/wifit3/chips/\*](https://github.com/derv82/wifit3/tree/master/src/wifit3/chips)) that directly control wireless devices over USB bulk and control transfers.

Because register-level frame injection and monitor mode are performed entirely in user space, Windows NDIS restrictions and Linux kernel driver locking do not apply.

For architecture details, driver porting methodology, and USB trace replay tooling, see the [Porting Documentation](https://github.com/derv82/wifit3/blob/master/docs/porting/METHODOLOGY.md).

## License & Disclaimer

**Code:** Licensed under [**GNU General Public License v2.0**](LICENSE) (matching upstream Linux drivers).

**Firmware:** Vendor firmware blobs loaded onto adapters are redistributed verbatim under their respective manufacturers' licenses (details in [FIRMWARE.md](docs/FIRMWARE.md)).

**⚠️ Notice & Disclaimer:** For use only on networks and equipment you own or are explicitly authorized to audit. wifit3 operates directly on USB hardware registers without kernel guardrails; use at your own risk.
