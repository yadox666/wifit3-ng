from __future__ import annotations

import hashlib
import os
import struct
import sys
from pathlib import Path

RTL_ROM_VERSION_OPCODE = 0xFC6D
RTL_DOWNLOAD_OPCODE = 0xFC20
RTL_FRAGMENT_LENGTH = 252
# FC20 uploads can take several seconds on slower hosts (see Linux btusb timeouts).
RTL_FIRMWARE_COMMAND_TIMEOUT_MS = 15_000

RTL8761BU_STOCK_LMP = 0x8761
RTL8761BU_PATCHED_LMP = 0xD922
RTL8761BU_HCI_VERSION = 0x0A
RTL8761BU_MANUFACTURER = 0x005D

_FIRMWARE_SHA256 = "1d7a9597349ad89344fa16c1913d3e39e9a12e966e417ca16871bc79bbe59edb"
_CONFIG_SHA256 = "6c28a3f07c6a30ed208c4b64862a23f02b7d93543ea980edd24df16bab45095f"
_EPATCH_SIGNATURE = b"Realtech"
_EXTENSION_SIGNATURE = b"\x51\x04\xfd\x77"
_CONFIG_SIGNATURE = b"\x55\xab\x23\x87"


class Rtl8761FirmwareError(RuntimeError):
    pass


def firmware_directory() -> Path:
    override = os.environ.get("WIFIT3_RTL8761_FIRMWARE")
    if override:
        return Path(override).expanduser()
    bundled = Path(getattr(sys, "_MEIPASS", "")) / "artifacts" / "rtl8761"
    if getattr(sys, "_MEIPASS", None) and bundled.is_dir():
        return bundled
    packaged = Path(__file__).resolve().parent / "firmware" / "rtl8761"
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[3] / "artifacts" / "rtl8761"


def load_download_image(rom_version: int) -> bytes:
    directory = firmware_directory()
    firmware = _verified_read(directory / "rtl8761bu_fw.bin", _FIRMWARE_SHA256)
    config = _verified_read(directory / "rtl8761bu_config.bin", _CONFIG_SHA256)
    patch = select_patch(firmware, rom_version)
    if not config.startswith(_CONFIG_SIGNATURE):
        raise Rtl8761FirmwareError("RTL8761BU config signature is invalid")
    return patch + config


def select_patch(firmware: bytes, rom_version: int) -> bytes:
    if len(firmware) < 18 or not firmware.startswith(_EPATCH_SIGNATURE):
        raise Rtl8761FirmwareError("RTL8761BU EPATCH signature is invalid")
    if not firmware.endswith(_EXTENSION_SIGNATURE):
        raise Rtl8761FirmwareError("RTL8761BU extension signature is invalid")
    firmware_version, patch_count = struct.unpack_from("<IH", firmware, 8)
    metadata_end = 14 + patch_count * 8
    if patch_count == 0 or metadata_end > len(firmware):
        raise Rtl8761FirmwareError("RTL8761BU patch metadata is truncated")
    chip_ids = struct.unpack_from(f"<{patch_count}H", firmware, 14)
    lengths_offset = 14 + patch_count * 2
    lengths = struct.unpack_from(f"<{patch_count}H", firmware, lengths_offset)
    offsets_offset = lengths_offset + patch_count * 2
    offsets = struct.unpack_from(f"<{patch_count}I", firmware, offsets_offset)
    wanted_chip_id = rom_version + 1
    try:
        index = chip_ids.index(wanted_chip_id)
    except ValueError as exc:
        raise Rtl8761FirmwareError(
            f"RTL8761BU firmware has no patch for ROM version {rom_version}"
        ) from exc
    offset, length = offsets[index], lengths[index]
    if length < 4 or offset > len(firmware) or length > len(firmware) - offset:
        raise Rtl8761FirmwareError("RTL8761BU patch range is invalid")
    patch = bytearray(firmware[offset:offset + length])
    patch[-4:] = struct.pack("<I", firmware_version)
    return bytes(patch)


def download_fragments(image: bytes):
    fragment_count = len(image) // RTL_FRAGMENT_LENGTH + 1
    sequence = 0
    for fragment_number in range(fragment_count):
        index = sequence
        sequence += 1
        if index == 0x7F:
            sequence = 1
        start = fragment_number * RTL_FRAGMENT_LENGTH
        data = image[start:start + RTL_FRAGMENT_LENGTH]
        if fragment_number == fragment_count - 1:
            index |= 0x80
        yield bytes([index]) + data


def _verified_read(path: Path, expected_sha256: str) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise Rtl8761FirmwareError(f"missing RTL8761BU firmware: {path}") from exc
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise Rtl8761FirmwareError(f"RTL8761BU firmware hash mismatch: {path.name}")
    return data
