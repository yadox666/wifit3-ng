import pytest

from wifit3.bluetooth.rtl8761_firmware import (
    Rtl8761FirmwareError,
    download_fragments,
    firmware_directory,
    load_download_image,
    select_patch,
)


def test_bundled_usb_firmware_selects_rom_one_patch_and_config():
    image = load_download_image(1)

    assert len(image) == 30210
    assert image[-6:] == bytes.fromhex("55ab23870000")
    assert image[-10:-6] == bytes.fromhex("22d9c6df")


def test_download_fragments_use_realtek_sequence_and_final_bit():
    image = load_download_image(1)
    fragments = list(download_fragments(image))

    assert len(fragments) == 120
    assert fragments[0][0] == 0
    assert fragments[-1][0] == (119 | 0x80)
    assert b"".join(fragment[1:] for fragment in fragments) == image


def test_firmware_hashes_match_manifest_payloads():
    directory = firmware_directory()

    assert (directory / "rtl8761bu_fw.bin").stat().st_size == 44484
    assert (directory / "rtl8761bu_config.bin").stat().st_size == 6


def test_patch_parser_rejects_wrong_signature():
    with pytest.raises(Rtl8761FirmwareError, match="signature"):
        select_patch(b"not-realtek-firmware", 1)
