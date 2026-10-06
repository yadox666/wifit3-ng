# Public sync review — port from `wifit3-ng-private` (branch `yadox-enhanced`)

Date: 2026-10-05
Scope: port the **allowed** uncommitted changes from the private enhanced tree
into the public repo (`wifit3-ng` / `yadox666/wifit3-ng`), **excluding** every
feature forbidden by `.cursor/rules/public-github-boundary.mdc`.

Approach: **copy + surgical strip** (copy the private version, remove forbidden
pieces, health-check per file), driven by the standing decisions:
`continue=full`, `history fingerprints=full_remove`, `targets=include except
fingerprints/unavailable`.

## Excluded (forbidden) feature set

Never ported (modules + their tests kept out of public):

- **Wi-Fi/BLE/AP fingerprinting**: `wlan/fingerprint.py`, `bluetooth/fingerprint.py`,
  `ui/fingerprint_format.py`, all HW/RF fingerprint columns, filters,
  sort keys, offline columns, target fingerprint matching, and the history
  fingerprint schema (fully removed from `ap_history` and `bluetooth_history`).
- **Operations / new-operation workflow**: `ui/operation.py`,
  `ui/screens/new_operation_modal.py`, operation-scope filtering.
- **RF Lab TX**: `ui/screens/rf_lab.py` and the `#rf-lab-btn` splash button.
- **Bluetooth USB lab**: `ui/screens/bluetooth_usb_lab.py`, `bluetooth/lab/**`,
  lab pairing/fuzz/GATT, `usb_lab_available` / `lab_routing_preflight`.
- **PortalTwin / captive-portal / SDR jam** — not present in public.
- **Wi-Fi regulatory-domain control (regdom-change)**: the user-facing
  "Wi‑Fi regulatory country (TX power & channels)" `Select` and its whole
  **Radio** preferences tab were removed from `ui/pref.py`
  (`RegulatoryCountrySetting`, `tab-radio`/`panel-radio`, and the
  `normalize_country(...)` save path). The compliance clamp
  `wlan/regulatory.py` is **kept** — it only *lowers* TX power to the
  configured cap and never runs `iw reg set`; with no UI control it defaults
  to world/`00` (most restrictive). Test
  `tests/ui/test_pref.py::test_regulatory_country_preference_can_be_saved`
  was removed accordingly.

Guard (clean): `rg -n "PortalTwin|portal_twin|bluetooth_usb_lab|bluetooth\.lab|rf_lab|lab_tx" src/`
→ no matches. All forbidden modules confirmed absent from `src/`, and no
forbidden test files exist under `tests/`.

## Allowed features ported

Core scanner UX, offline-DB catalog class/family + target columns, MAC
formatting, catalog editor/assign modal, search input, offline detail panels
(AP/client/bluetooth), Microsoft PnP identifiers, product-family **regex
catalog** (`stock_product_families.json` + `product_catalog.py`), GATT identity,
bluetooth observation links, location history, named scan sessions, targets
(except fingerprints), and the footer "keep shortcuts while a filter Input is
focused" helper (`ui/binding_display.py` + `active_bindings` overrides in
`scanner.py` / `offline.py`).

em-dash (U+2014) was replaced with `-` in ported `src/` files to satisfy
`tests/test_style.py::test_no_emdash_in_core`.

## Bug fixed in public (latent in private too)

`persist/bluetooth_history.py` migration step **15 → 16** (`ADD COLUMN ble_mac`)
was not idempotent: re-migrating a DB whose `user_version` was rolled back while
the physical column already existed raised `duplicate column name: ble_mac`,
which `_open()` swallows into `self.errors`, leaving `user_version` stuck at 15.
Fixed by guarding the `ALTER` with a `PRAGMA table_info` column check before the
version bump. **The private tree has the identical latent bug.**

## Notification dialog ported (per explicit request)

`ui/notification_center.py`: public previously shipped an **"expand"** notification
history modal (columns `marker/when/title/level/message`). The private **"preview"**
redesign (columns `when/title/level`, row-select live preview pane) was **ported on
request**, replacing the public design:

- `src/wifit3/ui/notification_center.py` — new preview dialog (3 em-dashes → `-`).
- `src/wifit3/persist/notifications.py` — ported the auto-title helper
  (`_default_title`, so missing titles default to `Warning` / `Error` / `Information`).
- `tests/ui/test_notification_persist.py` — ported to the new preview design.

Clean of forbidden tokens; full suite shows no regressions from this change.

## Test porting notes

- Ported M + new allowed test files, stripping forbidden cases (lab pairing
  tests, `usb_lab`, fingerprint filters/columns/sort/snapshots, operation modal).
- `tests/ui/test_confirm_active.py`: the example action label `"PortalTwin"` was
  renamed to `"Background monitor"` (string only; no behavior) to satisfy the
  public token guard.
- `tests/persist/test_ap_history.py` reverted to the public baseline (private
  version was dominated by removed fingerprint persistence tests).

## Current health check

`.venv/bin/python -m pytest -p no:cacheprovider -q`
→ **3756 passed, 14 failed, 2 skipped, 11 xfailed**.

### The 14 remaining failures are PRE-EXISTING in the private tree

Each was re-run read-only against the private working tree with the same
interpreter (`PYTHONPATH=<priv>/src`) and **fails identically there**, i.e. the
private source-of-truth is itself not green — these are unfinished private
features, not port artifacts. They must be resolved on the private side (or the
corresponding features completed) before public can be fully green.

Product catalog (regex matching / GATT rematch — incomplete private logic):
- `tests/observe/test_product_catalog.py::test_airtag_name_keeps_the_family_beside_an_apple_device`
- `tests/observe/test_product_catalog.py::test_field_ssid_clues_from_user_db`
- `tests/observe/test_product_catalog_user.py::test_prepare_device_catalog_rematches_on_gatt`
- `tests/observe/test_product_catalog_user.py::test_gatt_submodel_rule_matches_after_enrichment`
  - Note: these emit `FutureWarning: Possible nested set at position 8` from a
    regex in `stock_product_families.json` (`product_catalog.py:1124`); the
    catalog regex set likely needs escaping.

Bluetooth scanner (model caching / default sort — incomplete private logic):
- `tests/ui/test_bluetooth_scanner.py::test_bluetooth_scanner_shows_cached_device_model`
- `tests/ui/test_bluetooth_scanner.py::test_scanner_logs_learned_model_and_gates_enrichment_by_screen`
- `tests/ui/test_bluetooth_scanner.py::test_bluetooth_saved_target_row_is_red_and_marked`
- `tests/ui/test_bluetooth_scanner.py::test_default_sort_keeps_new_devices_at_the_bottom`
- `tests/ui/test_bluetooth_scanner.py::test_default_first_seen_order_stays_put_as_labels_tick`
- `tests/ui/test_bluetooth_scanner.py::test_first_seen_sort_uses_timestamps_not_formatted_ages`

Other:
- `tests/bluetooth/test_manager.py::test_manager_keeps_private_devices_live_without_persisting_them`
- `tests/bluetooth/test_connection.py::test_connection_enumerates_and_decodes_standard_descriptors`
- `tests/wlan/test_sink_picture.py::test_wpa3_and_pmf_flags_propagate_and_refresh`
  (`pmf_required` stays `True` after a beacon update sets it `False`)
- `tests/ui/test_app.py::test_app_layout_and_boot` — stale test: it calls
  `OfflineDatabaseView._toggle_record`, which the private offline redesign
  removed (replaced by the detail-panel API). The private dev did not update
  `test_app.py` (it is not in the private change set). Needs updating to the new
  offline API on the private side.

## Suggested follow-ups (private side)

1. Complete the catalog regex/GATT-rematch logic (4 catalog tests) and escape the
   nested-set regex in `stock_product_families.json`.
2. Finish bluetooth-scanner model caching + default-sort behavior (6 tests).
3. Fix `WlanSink` so `pmf_required=False` updates override a prior `True`.
4. Update `tests/ui/test_app.py` to the new offline detail-panel API.
5. Port the migration idempotency fix (see above) back to private.
