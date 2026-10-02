from unittest.mock import patch

import pytest
from textual.widgets import DataTable, Static

from wifit3.ui.app import WifiteApp, _notification_should_persist
from wifit3.ui.notification_center import NotificationHistoryModal


def test_should_persist_defaults_to_warning_and_error_only():
    assert _notification_should_persist("information", None) is False
    assert _notification_should_persist("info", None) is False
    assert _notification_should_persist("warning", None) is True
    assert _notification_should_persist("error", None) is True
    assert _notification_should_persist("information", True) is True
    assert _notification_should_persist("error", False) is False


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_information_toast_not_stored_unless_persist(tmp_path, monkeypatch):
    from wifit3.persist.notifications import NotificationStore

    store_path = tmp_path / "notifications.sqlite3"
    monkeypatch.setattr(
        "wifit3.ui.app.NotificationStore",
        lambda: NotificationStore(store_path),
    )

    app = WifiteApp()
    async with app.run_test():
        app.notify("Sorted by RSSI", title="Sort changed")
        assert app.notification_store.unread_count() == 0

        app.notify("Disk full", title="Config", severity="error")
        assert app.notification_store.unread_count() == 1

        with patch.object(app.__class__.__bases__[0], "notify") as super_notify:
            app.notify("Target seen", title="Target in range", persist=True)
            super_notify.assert_called_once()
            assert app.notification_store.unread_count() == 2


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_notification_row_expands_and_copies_full_message(tmp_path, monkeypatch):
    from wifit3.persist.notifications import NotificationStore

    store_path = tmp_path / "notifications.sqlite3"
    monkeypatch.setattr(
        "wifit3.ui.app.NotificationStore",
        lambda: NotificationStore(store_path),
    )
    copied: list[str] = []
    message = (
        "Classic device is not reachable. Re-run inquiry and verify that the "
        "device remains discoverable before retrying SDP."
    )
    app = WifiteApp()
    monkeypatch.setattr(app, "copy_to_clipboard", copied.append)
    app.notification_store.append(
        message,
        title="Classic SDP failed",
        severity="error",
    )

    async with app.run_test(size=(110, 38)) as pilot:
        app.action_notification_history()
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, NotificationHistoryModal)
        table = modal.query_one("#notify-table", DataTable)
        table.focus()
        await pilot.press("enter")
        await pilot.pause()

        assert modal.query_one("#notify-detail").has_class("expanded")
        assert modal.query_one(
            "#notify-detail-message",
            Static,
        ).render().plain == message

        await pilot.press("c")
        assert len(copied) == 1
        assert "Classic SDP failed" in copied[0]
        assert message in copied[0]
