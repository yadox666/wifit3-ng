from wifit3.persist.notifications import NotificationStore


def test_notification_store_round_trips_and_marks_read(tmp_path):
    path = tmp_path / "notifications.sqlite3"
    store = NotificationStore(path)
    store.append("Target seen", title="Target in range", severity="information")
    store.append("Disk full", title="Config", severity="error")
    assert store.unread_count() == 2
    recent = store.recent(limit=60)
    assert len(recent) == 2
    assert recent[0].message == "Disk full"
    store.mark_all_read()
    assert store.unread_count() == 0
    store.close()
