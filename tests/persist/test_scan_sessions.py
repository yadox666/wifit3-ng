from wifit3.persist.scan_sessions import generate_session_name, new_scan_session


def test_generated_session_name_is_two_or_three_dictionary_words():
    for _ in range(25):
        words = generate_session_name().split("-")
        assert len(words) in (2, 3)
        assert all(word.isalpha() and word.islower() for word in words)
        assert len(words) == len(set(words))


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
