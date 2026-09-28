# Wifit3 — Features & QoL Backlog

Known bugs live in `BUGS.md`.

---

### About page / Check-for-updates

If the user has internet connection, it's trivial to query
[the releases page](https://github.com/derv82/wifit3/releases) to fectch the latest version,
compare with the current version, and show a Toast notification about the newest version,
clicking Toast notification -> opens releases page.

We could automate this as well (opt-**in**), in Preferences: `[x] Automatically check for updates`

### VAULT — loot manager ("HACKLEBOX") — DONE (core view; Check/Hashcat/add deferred)

**Problem.** Half of Wifite's UX is effectively the OS file manager: squinting at `captures/` full
of long BSSID-encoded filenames. The loot (handshakes, PMKIDs, cracked PSKs) deserves a real view,
not a directory listing.

**Shipped.** `ui/screens/vault.py:VaultView`, opened from the Scanner (hotkey `v`) -- read-only
otherwise, no radio/interface dependency, works with no card plugged in. One `DataTable` over
`persist.capture_history.load_capture_index()` (already existed, built for the Scanner's own
capture-badge history -- VAULT is genuinely "just a new screen over" it, per the original
complexity note), newest-first, re-scanned from disk on every visit (`on_screen_resume`) so a
save from a running campaign shows up next time you open it. `PersistedCapture` gained an `ssid`
field (parsed from the filename, previously discarded) so the table can show a name, not just a
BSSID. Per-entry: **Remove** (`r`, deletes the file + reloads), **Copy** (`c`, the WEP/WPS
credential itself, or -- since HS/PMKID have no single "value" -- the file's own hashcat hashline
content, via Textual's native OSC-52 clipboard). Bulk: **Export all as Zip** (`z`, always written
*beside* `captures/`, never inside it, so a re-export can never bundle a previous export into
itself) and **Show directory** (`o`, `xdg-open`/`open`/`explorer` per platform). Verified with a
real Textual SVG render (title bar, columns, newest-first ordering, footer keybindings all
correct), not just unit assertions.

**Deferred, not attempted:**
- **"add" (manually enter a credential you already have from elsewhere).** No design decided yet
  for the entry form; low value next to the read/remove/copy path that's actually built.
- **Check button** (re-authenticate against the live AP to confirm a stored PSK still works).
  Needs a real target AP in range to test meaningfully, and VAULT has no "current target"/card
  context to decide which interface would even attempt it -- a class-design question for a
  session with hardware in the loop, not a solo overnight guess.
- **Launch Hashcat** (subprocess launch of an external tool). Spawning and babysitting an external
  process has real UX questions (detached terminal? inline output? which mode per capture type?)
  worth a quick design pass rather than silently picking conventions unasked.

------------

### EAP-MSCHAPv2 / PEAP via Evil Twin — DONE (PEAP lab honeypot; no deauth twin)

**Shipped.** From AP Focus → **Enterprise** → **Start PEAP EAP lab honeypot**: a spoofable
radio advertises a locally administered twin BSSID with the target ESSID and cloned 802.1X
RSN, runs outer **PEAP** with an ephemeral lab TLS certificate (OpenSSL-generated under the
private data dir), and captures inner **MS-CHAPv2** responses. Hash lines are written to
Vault as `*_mschapv2.mschapv2` (Hashcat **`-m 5500`**). Vault Hashcat launch picks the mode
from the file extension (22000 vs 5500).

**Also shipped:** optional **deauth + CSA + BTM** eviction bursts (respecting PMF) toward
the lab twin; outer **PEAP**, **EAP-TTLS**, and **EAP-TLS** (client-certificate request);
Vault writes paired **`5500`** (`*.mschapv2`) and **`5600` NetNTLMv2-SSP** (`*.netntlmv2`)
files. Hashcat mode **4800** is iSCSI CHAP in current Hashcat, not NetNTLMv2.

Beacons/probes **clone the observed target AP** when a live beacon is available (RSN
rewritten to a single 802.1X AKM; SAE/RSNXE stripped).

------------

### Enterprise client misconfiguration assessment — DONE

**Shipped** as part of the EAP lab honeypot (`EapLabLaunchConfig` + modal toggles):

- **Untrusted TLS** (lab cert) with per-client outcomes and `MISCONFIG` timeline lines.
- **Outer downgrade probe:** optional **weak outer EAP first** (reversed method order).
- **Inner PAP probe** before MS-CHAPv2 (inner NAK falls through to MS-CHAPv2).
- **Empty MS-CHAPv2** flagged when NT-Response is all zeros.
- **EAP-TLS Success** against the lab cert recorded as misconfiguration.
- **Lab DHCP Offer/ACK** on `10.99.0.0/24` (isolated; no routing).
- **`_eap_lab_report.json`** in Vault (pseudonymized client IDs, findings, outcomes)
  saved automatically when the lab ends with client evidence.

**Manual correlation:** probe honeypot still **observes** DHCP on OPEN/WPA2 fakes;
compare pseudonymized lab report entries with honeypot client MACs offline.

**SECURITY NOTES:** Authorized testing only; lab DHCP is isolated; findings are
observed client behavior, not org-wide policy proof.

------------

## Deferred / Chopping Block

### WPS improvements - Low priority (who even has a vulnerable WPS router?)

The WPS engine is built, offline-proven, and HW-validated (full PIN crack on AirLink). Gaps:
- **Lock-cycle matrix** — only AirLink soft-lock tested; exercise no-lock, long cooldowns, hard-lock.
- **PixieDust (PRNG seed recovery)** — Phase 1 (Null Secret) and Phase 2 (Static Secrets)
  landed natively in `campaigns/wps/pixie.py`. Advanced PRNG seed-search modes (Broadcom
  timestamp search, Realtek/MediaTek LCG) remain deferred due to the CPU cost of
  evaluating 32-bit seed spaces in pure Python.
