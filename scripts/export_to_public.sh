#!/usr/bin/env bash
# Apply reviewed diffs from this private tree onto wifit3-ng-public.
# Never bulk-sync the full repo — use named batches only.
set -euo pipefail

PRIVATE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PUBLIC_ROOT="${PUBLIC_ROOT:-/Users/yhansen/Downloads/To_Test/wifit3-ng-public}"
PUBLIC_REF="${PUBLIC_REF:-public/yadox-enhanced}"

die() { echo "export_to_public: $*" >&2; exit 1; }
[[ -d "$PUBLIC_ROOT/.git" ]] || die "missing public repo at $PUBLIC_ROOT"

cd "$PRIVATE_ROOT"
git rev-parse --verify "$PUBLIC_REF" >/dev/null 2>&1 || die "unknown ref $PUBLIC_REF"

apply_diff() {
  local path="$1"
  git diff "$PUBLIC_REF" HEAD -- "$path" | git -C "$PUBLIC_ROOT" apply --3way
}

copy_file() {
  local path="$1"
  local dest="$PUBLIC_ROOT/$path"
  mkdir -p "$(dirname "$dest")"
  cp "$PRIVATE_ROOT/$path" "$dest"
}

strip_rf_lab_for_public() {
  python3 "$PRIVATE_ROOT/scripts/strip_rf_lab_for_public.py" "$PUBLIC_ROOT"
}

verify_no_forbidden() {
  local root="$PUBLIC_ROOT"
  if rg -q 'portal_twin_modal|bluetooth_usb_lab' "$root/src" 2>/dev/null; then
    die "forbidden private-only UI found under public src"
  fi
  if rg '^from wifit3\.bluetooth\.lab|^import wifit3\.bluetooth\.lab' "$root/src" 2>/dev/null; then
    die "top-level bluetooth.lab import in public src"
  fi
  if rg -q 'from \.screens\.rf_lab|RfLabTxView|start_rf_lab' "$root/src/wifit3/ui" 2>/dev/null; then
    die "RF lab UI leaked into public tree"
  fi
}

patch_focus_leave() {
  python3 - <<'PY'
from pathlib import Path

def drop_passive_leave(path: Path) -> bool:
    text = path.read_text()
    block = (
        "        if self._network_analyzer is not None:\n"
        '            add("Passive network metadata")\n'
    )
    block_client = (
        "        if self._network_analyzer is not None:\n"
        '            actions.append("Passive network metadata")\n'
    )
    changed = False
    if block in text:
        text = text.replace(block, "")
        changed = True
    if block_client in text:
        text = text.replace(block_client, "")
        changed = True
    if changed:
        path.write_text(text)
    return changed

public = Path("/Users/yhansen/Downloads/To_Test/wifit3-ng-public")
paths = [
    public / "src/wifit3/ui/screens/focus_v2/screen.py",
    public / "src/wifit3/ui/screens/focus_v2/client_focus_screen.py",
]
ok = all(drop_passive_leave(p) for p in paths)
if not ok:
    raise SystemExit("focus-leave: expected passive-metadata blocks not found")
PY
}

batch_focus_leave() {
  patch_focus_leave
  echo "Applied batch: focus-leave"
}

batch_sessions_observe() {
  for f in \
    src/wifit3/observe/__init__.py \
    src/wifit3/observe/remote_id.py \
    src/wifit3/observe/signature_pack.py \
    src/wifit3/observe/stock_signatures.json \
    src/wifit3/observe/tracker_state.py \
    src/wifit3/persist/scan_sessions.py
  do
    copy_file "$f"
  done
  for f in \
    src/wifit3/persist/ap_history.py \
    src/wifit3/persist/bluetooth_history.py \
    src/wifit3/ui/app.py \
    src/wifit3/dot11/parser.py \
    src/wifit3/bluetooth/analytics.py \
    src/wifit3/models/capabilities.py \
    src/wifit3/ui/pref.py \
    src/wifit3/ui/scan_export.py \
    src/wifit3/ui/screens/offline.py \
    src/wifit3/ui/screens/scanner.py \
    src/wifit3/ui/screens/splash.py \
    src/wifit3/persist/notifications.py \
    src/wifit3/ui/notification_center.py
  do
    apply_diff "$f" || copy_file "$f"
  done
  for f in \
    tests/observe/test_signature_pack.py \
    tests/persist/test_scan_sessions.py \
    tests/persist/test_ap_history.py \
    tests/persist/test_bluetooth_history.py \
    tests/persist/test_notifications.py \
    tests/ui/test_background_monitor.py \
    tests/ui/test_offline.py \
    tests/ui/test_offline_filter.py \
    tests/ui/test_notification_persist.py \
    tests/ui/test_pref.py \
    tests/ui/test_scanner_ap_columns.py
  do
    apply_diff "$f" || copy_file "$f"
  done
  strip_rf_lab_for_public
  verify_no_forbidden
  echo "Applied batch: sessions-observe (RF lab UI stripped from app/splash)"
}

batch_vault_targeting() {
  for f in \
    src/wifit3/persist/vault.py \
    src/wifit3/ui/screens/vault_drawer.py \
    src/wifit3/ui/screens/vault_import.py \
    src/wifit3/targeting.py \
    src/wifit3/ui/screens/targets_editor.py \
    src/wifit3/ui/screens/targets.py
  do
    copy_file "$f"
  done
  for f in \
    tests/persist/test_vault.py \
    tests/ui/test_vault.py \
    tests/ui/test_vault_import.py \
    tests/ui/test_targets_editor_context.py \
    tests/targeting/test_match.py \
    tests/targeting/test_observation_summary.py \
    tests/targeting/test_offline_candidate.py \
    tests/persist/test_targets.py
  do
    [[ -f "$PRIVATE_ROOT/$f" ]] && copy_file "$f"
  done
  verify_no_forbidden
  echo "Applied batch: vault-targeting"
}

batch_rf_spectrum_readonly() {
  for f in \
    src/wifit3/sdr/__init__.py \
    src/wifit3/sdr/hackrf.py \
    src/wifit3/sdr/sweep.py \
    src/wifit3/ui/screens/sdr_picker.py \
    src/wifit3/ui/screens/spectrum.py
  do
    copy_file "$f"
  done
  verify_no_forbidden
  echo "Applied batch: rf-spectrum-readonly (no lab_tx)"
}

batch_session_start_dialog() {
  batch_rf_spectrum_readonly
  for f in \
    src/wifit3/persist/scan_sessions.py \
    src/wifit3/persist/ap_history.py \
    src/wifit3/persist/bluetooth_history.py \
    src/wifit3/ui/screens/session_start_modal.py \
    tests/persist/test_scan_sessions.py \
    tests/ui/test_session_start_modal.py
  do
    copy_file "$f"
  done
  apply_diff src/wifit3/ui/app.py || copy_file src/wifit3/ui/app.py
  apply_diff tests/ui/conftest.py || copy_file tests/ui/conftest.py
  apply_diff tests/persist/test_ap_history.py || true
  apply_diff tests/persist/test_bluetooth_history.py || true
  strip_rf_lab_for_public
  verify_no_forbidden
  echo "Applied batch: session-start-dialog"
}

batch_bt_usb_claim() {
  for f in \
    src/wifit3/persist/bluetooth_bonds.py \
    src/wifit3/ui/screens/bluetooth_picker.py \
    src/wifit3/bluetooth/gatt_att.py \
    src/wifit3/bluetooth/usb_gatt.py \
    src/wifit3/bluetooth/usb_claim.py \
    src/wifit3/bluetooth/usb_capabilities.py \
    src/wifit3/bluetooth/usb_connection.py \
    src/wifit3/bluetooth/usb_hci.py \
    src/wifit3/bluetooth/apple_identifiers.py \
    src/wifit3/bluetooth/gatt_metadata.py \
    src/wifit3/bluetooth/connection.py \
    src/wifit3/bluetooth/hci_protocol.py \
    src/wifit3/bluetooth/rtl8761_firmware.py \
    src/wifit3/bluetooth/assigned_numbers.py \
    src/wifit3/bluetooth/manager.py \
    src/wifit3/models/__init__.py \
    src/wifit3/models/bluetooth_device.py \
    src/wifit3/models/bluetooth_inspection.py \
    src/wifit3/persist/bluetooth_history.py \
    src/wifit3/ui/screens/bluetooth_scanner.py \
    src/wifit3/ui/screens/bluetooth_focus.py \
    src/wifit3/ui/screens/bluetooth_classic_focus.py \
    scripts/bluetooth_usb_reclaim_probe.py
  do
    copy_file "$f"
  done
  if [[ -d "$PRIVATE_ROOT/src/wifit3/bluetooth/data" ]]; then
    rm -rf "$PUBLIC_ROOT/src/wifit3/bluetooth/data"
    cp -R "$PRIVATE_ROOT/src/wifit3/bluetooth/data" "$PUBLIC_ROOT/src/wifit3/bluetooth/data"
  fi
  for f in \
    tests/bluetooth/test_usb_claim.py \
    tests/bluetooth/test_usb_hci.py \
    tests/bluetooth/test_usb_connection.py \
    tests/bluetooth/test_connection.py \
    tests/bluetooth/test_hci_protocol.py \
    tests/bluetooth/test_assigned_numbers.py \
    tests/bluetooth/test_apple_identifiers.py \
    tests/bluetooth/test_gatt_identity.py \
    tests/bluetooth/test_manager.py \
    tests/ui/test_bluetooth_scanner.py \
    tests/ui/test_bluetooth_focus.py \
    tests/ui/test_bluetooth_classic_focus.py \
    tests/persist/test_bluetooth_history.py \
    tests/persist/test_bluetooth_bonds.py
  do
    [[ -f "$PRIVATE_ROOT/$f" ]] && copy_file "$f"
  done
  python3 "$PRIVATE_ROOT/scripts/strip_bt_lab_for_public.py" "$PUBLIC_ROOT"
  verify_no_forbidden
  echo "Applied batch: bt-usb-claim (lab UI/methods stripped)"
}

batch_all() {
  python3 "$PRIVATE_ROOT/scripts/sync_private_to_public.py" "$PUBLIC_ROOT" "$PUBLIC_REF"
  verify_no_forbidden
  echo "Applied batch: all (RF/BT lab, PortalTwin, regdom-change excluded)"
}

case "${1:-}" in
  focus-leave) batch_focus_leave ;;
  sessions-observe) batch_sessions_observe ;;
  rf-spectrum-readonly) batch_rf_spectrum_readonly ;;
  session-start-dialog) batch_session_start_dialog ;;
  vault-targeting) batch_vault_targeting ;;
  bt-usb-claim) batch_bt_usb_claim ;;
  all) batch_all ;;
  verify) verify_no_forbidden ;;
  *)
    echo "Usage: $0 {focus-leave|sessions-observe|rf-spectrum-readonly|session-start-dialog|vault-targeting|bt-usb-claim|all|verify}" >&2
    echo "  PUBLIC_ROOT=... PUBLIC_REF=public/yadox-enhanced $0 <batch>" >&2
    exit 1
    ;;
esac
