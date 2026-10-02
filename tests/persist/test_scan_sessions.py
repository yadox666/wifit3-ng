import json

from wifit3.persist.scan_sessions import (
    allocate_session_name,
    collect_session_metadata,
    generate_session_name,
    merge_session_metadata,
    new_scan_session,
    persisted_session_names,
    session_end_metadata_patch,
)


def test_generated_session_name_is_two_or_three_dictionary_words():
    for _ in range(25):
        words = generate_session_name().split("-")
        assert len(words) in (2, 3)
        assert all(word.isalpha() and word.islower() for word in words)
        assert len(words) == len(set(words))


def test_generate_session_name_skips_persisted_labels():
    existing = {"cedar-orbit", "Site-Alpha"}
    for _ in range(40):
        name = generate_session_name(existing)
        assert name.casefold() not in {n.casefold() for n in existing}


def test_allocate_session_name_respects_db_and_regenerates_on_collision():
    assert allocate_session_name("custom-run", {"custom-run"}) != "custom-run"
    assert allocate_session_name("custom-run", {"other"}) == "custom-run"
    assert allocate_session_name("  ", {"other"}) != ""


def test_persisted_session_names_reads_scan_sessions_rows():
    class _Store:
        def scan_sessions(self):
            return [{"name": "cedar-orbit"}, {"name": "lobby-pass"}]

    assert persisted_session_names(_Store()) == {"cedar-orbit", "lobby-pass"}


def test_new_session_replaces_duplicate_explicit_name():
    session = new_scan_session(
        {"wifi"},
        mode="app",
        name="cedar-orbit",
        existing_names={"cedar-orbit"},
    )
    assert session.name.casefold() != "cedar-orbit"


def test_new_session_normalizes_media_and_avoids_existing_name():
    first = new_scan_session({"WiFi", "BLUETOOTH"}, mode="background")
    second = new_scan_session(
        {"wifi"},
        mode="wifi",
        existing_names={first.name},
    )

    assert first.media == frozenset({"wifi", "bluetooth"})
    assert first.id != second.id
    assert first.name != second.name


def test_new_session_accepts_custom_name_description_and_metadata():
    session = new_scan_session(
        {"wifi"},
        mode="app",
        name="site-alpha",
        description="Lobby survey",
        metadata={"mode": "app", "wifit3_version": "0.0.0"},
    )
    assert session.name == "site-alpha"
    assert session.description == "Lobby survey"
    meta = json.loads(session.metadata_json)
    assert meta["wifit3_version"] == "0.0.0"


def test_collect_session_metadata_includes_platform():
    meta = collect_session_metadata(
        mode="app",
        wifit3_version="1.2.3",
        started_at=1_700_000_000.0,
    )
    assert meta["mode"] == "app"
    assert meta["wifit3_version"] == "1.2.3"
    assert "platform" in meta
    assert meta["started_at_utc"].endswith("Z")


def test_session_end_metadata_patch():
    patch = session_end_metadata_patch(1_700_000_100.0)
    assert patch["ended_at_utc"].endswith("Z")
    merged = merge_session_metadata('{"mode":"app"}', patch)
    assert "ended_at_utc" in json.loads(merged)
