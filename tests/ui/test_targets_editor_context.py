import pytest
from textual.app import App
from textual.widgets import Button, Input, Select, Static

from wifit3.models import AccessPoint
from wifit3.persist.targets import TargetStore
from wifit3.targeting import TargetCandidate, infrastructure_candidate
from wifit3.ui.screens.bluetooth_scanner import BluetoothScannerView
from wifit3.ui.screens.offline import OfflineDatabaseView
from wifit3.ui.screens.scanner import ScannerView
from wifit3.ui.screens.targets_editor import TargetsEditorDrawer


class _Host(App):
    def __init__(self, path, candidate: TargetCandidate) -> None:
        super().__init__()
        self.target_store = TargetStore(path)
        self.candidate = candidate

    def on_mount(self) -> None:
        self.push_screen(TargetsEditorDrawer(prefill=self.candidate))


def _candidate() -> TargetCandidate:
    return TargetCandidate(
        medium="wifi",
        kind="ap",
        identifier="aa:bb:cc:dd:ee:ff",
        title="Office",
        details={"ssid": "Office", "channel": 6},
    )


@pytest.mark.asyncio
async def test_new_uses_row_context_without_starting_in_draft(tmp_path):
    app = _Host(tmp_path / "targets.sqlite3", _candidate())
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, TargetsEditorDrawer)
        assert (
            modal.query_one("#targets-detail-title", Static).render().plain
            == "Select an entry"
        )

        modal.query_one("#targets-new", Button).press()
        await pilot.pause()

        assert modal.query_one("#targets-detail-title", Static).render().plain == "New target"
        assert (
            modal.query_one("#targets-identifier", Input).value
            == "aa:bb:cc:dd:ee:ff"
        )
        assert "Office" in modal.query_one("#targets-detail-fields", Static).render().plain
    app.target_store.close()


def test_scanners_expose_only_the_targets_menu_binding():
    for screen_type in (ScannerView, BluetoothScannerView, OfflineDatabaseView):
        bindings = [
            (binding.key, binding.action)
            for binding in screen_type.BINDINGS
            if "target" in binding.action
        ]
        assert bindings == [("shift+t", "targets_editor")]


@pytest.mark.asyncio
async def test_collapsed_infrastructure_creates_ssid_security_draft(tmp_path):
    members = [
        AccessPoint(
            bssid=f"aa:bb:cc:dd:ee:{suffix}",
            ssid="Office mesh",
            channel=channel,
            encryption="WPA2",
            akms=["PSK", "SAE"],
            wpa3=True,
            transition_mode=True,
        )
        for suffix, channel in (("01", 1), ("02", 6), ("03", 11))
    ]
    candidate = infrastructure_candidate(members)
    assert candidate is not None
    assert candidate.match_mode == "name"
    assert candidate.identifier == "Office mesh"
    assert candidate.details["encryption"] == "WPA2/3-PSK"

    app = _Host(tmp_path / "targets.sqlite3", candidate)
    async with app.run_test(size=(100, 32)) as pilot:
        await pilot.pause()
        modal = app.screen
        modal.query_one("#targets-new", Button).press()
        await pilot.pause()

        assert modal.query_one("#targets-match-mode", Select).value == "name"
        assert modal.query_one("#targets-identifier", Input).value == "Office mesh"
        preview = modal.query_one("#targets-detail-fields", Static).render().plain
        assert "3 APs by SSID" in preview
        assert "WPA2/3-PSK" in preview
    app.target_store.close()
