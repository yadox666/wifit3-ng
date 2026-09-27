"""Minimal libpcap writer for raw 802.11 frames.

Produces a standard libpcap-format file (NOT pcapng) with linktype
``LINKTYPE_IEEE802_11`` (105). Suitable for handing to ``hcxpcapngtool``
(which accepts both pcap and pcapng) → ``hashcat -m 22000``.
"""

from __future__ import annotations

import re
import struct
import threading
import time
from pathlib import Path
from typing import Iterable

LINKTYPE_IEEE802_11 = 105
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION = (2, 4)
SNAPLEN = 65535


class PcapWriter:
    """Thread-safe streaming writer for raw 802.11 libpcap files."""

    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int | None = None,
        max_parts: int = 10,
    ) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = path.open("wb")
        self._lock = threading.Lock()
        self._closed = False
        self._max_bytes = max_bytes
        self._max_parts = max_parts
        self.paths = [path]
        self._completed_bytes = 0
        self.count = 0
        self.dropped = 0
        self._write_header()

    def _write_header(self) -> None:
        self._stream.write(struct.pack(
            "<IHHiIII",
            PCAP_MAGIC,
            PCAP_VERSION[0],
            PCAP_VERSION[1],
            0,
            0,
            SNAPLEN,
            LINKTYPE_IEEE802_11,
        ))

    def _rotate(self) -> bool:
        if self._max_parts > 0 and len(self.paths) >= self._max_parts:
            return False
        self._completed_bytes += self._stream.tell()
        self._stream.flush()
        self._stream.close()
        match = re.match(r"^(.*_)(\d+)(_packet_capture\.pcap)$", self.path.name)
        if match:
            next_name = (
                f"{match.group(1)}{int(match.group(2)) + len(self.paths)}"
                f"{match.group(3)}"
            )
        else:
            next_name = f"{self.path.stem}_part{len(self.paths) + 1}.pcap"
        next_path = self.path.with_name(next_name)
        self._stream = next_path.open("wb")
        self.paths.append(next_path)
        self._write_header()
        return True

    def write(self, frame: bytes, timestamp: float | None = None) -> bool:
        if not frame:
            return False
        captured_at = timestamp if timestamp and timestamp > 0 else time.time()
        seconds = int(captured_at)
        microseconds = int((captured_at - seconds) * 1_000_000)
        length = len(frame)
        with self._lock:
            if self._closed:
                return False
            record_bytes = 16 + length
            if (
                self._max_bytes is not None
                and self._stream.tell() > 24
                and self._stream.tell() + record_bytes > self._max_bytes
                and not self._rotate()
            ):
                self.dropped += 1
                return False
            self._stream.write(struct.pack(
                "<IIII", seconds, microseconds, length, length,
            ))
            self._stream.write(frame)
            self.count += 1
        return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._completed_bytes += self._stream.tell()
            self._stream.flush()
            self._stream.close()
            self._closed = True

    @property
    def total_bytes(self) -> int:
        """Current bytes across every rotated part, including libpcap headers."""
        with self._lock:
            if self._closed:
                return self._completed_bytes
            return self._completed_bytes + self._stream.tell()

    @property
    def part_count(self) -> int:
        with self._lock:
            return len(self.paths)

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, *_args) -> None:
        self.close()


def write_pcap(path: Path, records: Iterable[tuple[bytes, float]]) -> int:
    """Write *records*, ``(raw 802.11 frame, capture timestamp)`` pairs, to a
    pcap at *path*. The timestamp is epoch seconds (float).

    Per-frame timing is preserved so the file is forensically accurate AND
    re-extractable by ``hcxpcapngtool``, which pairs EAPOL frames by their
    timestamps (an EAPOL timeout window). Identical stamps would make it
    mis-pair. A timestamp <= 0 (unset) falls back to the current wall-clock
    time so the frame still lands with a sane epoch.

    Returns the number of frames written.
    """
    with PcapWriter(path) as writer:
        for frame, ts in records:
            writer.write(frame, ts)
    return writer.count
