from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable

try:
    import serial
    from serial.tools import list_ports
except ModuleNotFoundError:
    serial = None
    list_ports = None

from wifit3.models.location import LocationFix


_BAUDRATES = (4800, 9600, 38400, 19200, 57600, 115200)
_NMEA_PREFIXES = ("$GPGGA,", "$GNGGA,", "$GPRMC,", "$GNRMC,")


@dataclass(frozen=True, slots=True)
class GpsStatus:
    port: str
    baudrate: int


class GpsManager:
    def __init__(
        self,
        *,
        port: str = "",
        on_detected: Callable[[GpsStatus], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self.configured_port = port.strip()
        self.on_detected = on_detected
        self.on_error = on_error
        self.latest_fix: LocationFix | None = None
        self.status: GpsStatus | None = None
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    @property
    def dependency_available(self) -> bool:
        return serial is not None and list_ports is not None

    @property
    def is_searching(self) -> bool:
        return self._task is not None and not self._task.done() and self.status is None

    def start(self) -> None:
        if not self.dependency_available:
            if self.on_error is not None:
                self.on_error("Serial GPS support requires the pyserial package")
            return
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        task, self._task = self._task, None
        if task is not None:
            await task

    async def reconfigure(self, port: str) -> None:
        await self.stop()
        self.configured_port = port.strip()
        self.latest_fix = None
        self.status = None
        self.start()

    async def _run(self) -> None:
        while not self._stop.is_set():
            detected = await asyncio.to_thread(self._detect)
            if detected is None:
                await self._wait(5.0)
                continue
            port, baudrate = detected
            self.status = GpsStatus(port, baudrate)
            if self.on_detected is not None:
                self.on_detected(self.status)
            await asyncio.to_thread(self._read_until_disconnected, port, baudrate)
            self.status = None
            if not self._stop.is_set():
                await self._wait(2.0)

    async def _wait(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=seconds)
        except TimeoutError:
            pass

    def _detect(self) -> tuple[str, int] | None:
        for port in self._candidate_ports():
            for baudrate in _BAUDRATES:
                if self._stop.is_set():
                    return None
                if _probe_nmea(port, baudrate):
                    return port, baudrate
        return None

    def _candidate_ports(self) -> list[str]:
        if list_ports is None:
            return []
        if self.configured_port:
            return [self.configured_port]
        ports = list(list_ports.comports())
        likely = sorted(
            ports,
            key=lambda port: (
                not (
                    port.vid == 0x067B
                    or "gps" in (port.description or "").casefold()
                    or "gnss" in (port.description or "").casefold()
                ),
                port.device,
            ),
        )
        return [
            port.device for port in likely
            if not any(
                ignored in port.device.casefold()
                for ignored in ("bluetooth", "debug-console", "wlan-debug")
            )
        ]

    def _read_until_disconnected(self, port: str, baudrate: int) -> None:
        state: dict[str, object] = {}
        try:
            with serial.Serial(port, baudrate, timeout=0.5) as stream:
                while not self._stop.is_set():
                    raw = stream.readline()
                    if not raw:
                        continue
                    fix = parse_nmea_line(raw.decode("ascii", "ignore"), state)
                    if fix is not None:
                        self.latest_fix = fix
        except (OSError, serial.SerialException):
            return


def _probe_nmea(port: str, baudrate: int) -> bool:
    if serial is None:
        return False
    deadline = time.monotonic() + 1.6
    try:
        with serial.Serial(port, baudrate, timeout=0.25) as stream:
            stream.reset_input_buffer()
            while time.monotonic() < deadline:
                line = stream.readline().decode("ascii", "ignore").strip()
                if line.startswith(_NMEA_PREFIXES) and _checksum_ok(line):
                    return True
    except (OSError, serial.SerialException):
        pass
    return False


def parse_nmea_line(line: str, state: dict[str, object]) -> LocationFix | None:
    line = line.strip()
    if not line.startswith(_NMEA_PREFIXES) or not _checksum_ok(line):
        return None
    fields = line.split("*", 1)[0].split(",")
    sentence = fields[0][-3:]
    try:
        if sentence == "GGA":
            quality = int(fields[6] or 0)
            if quality <= 0:
                return None
            latitude = _coordinate(fields[2], fields[3])
            longitude = _coordinate(fields[4], fields[5])
            hdop = float(fields[8] or 99.0)
            state.update(
                latitude=latitude,
                longitude=longitude,
                altitude_m=float(fields[9]) if fields[9] else None,
                accuracy_m=max(1.0, hdop * 5.0),
                satellites=int(fields[7] or 0),
                fix_quality=quality,
            )
        elif sentence == "RMC":
            if fields[2] != "A":
                return None
            state.update(
                latitude=_coordinate(fields[3], fields[4]),
                longitude=_coordinate(fields[5], fields[6]),
            )
        if "latitude" not in state or "accuracy_m" not in state:
            return None
        return LocationFix(
            latitude=float(state["latitude"]),
            longitude=float(state["longitude"]),
            altitude_m=state.get("altitude_m"),
            accuracy_m=float(state["accuracy_m"]),
            observed_at=time.time(),
            source=f"nmea:{sentence.lower()}",
            satellites=int(state["satellites"]) if "satellites" in state else None,
            fix_quality=int(state["fix_quality"]) if "fix_quality" in state else None,
        )
    except (IndexError, TypeError, ValueError):
        return None


def _coordinate(value: str, hemisphere: str) -> float:
    raw = float(value)
    degrees = int(raw // 100)
    coordinate = degrees + (raw - degrees * 100) / 60
    return -coordinate if hemisphere in {"S", "W"} else coordinate


def _checksum_ok(line: str) -> bool:
    if not line.startswith("$") or "*" not in line:
        return False
    body, expected = line[1:].split("*", 1)
    checksum = 0
    for char in body:
        checksum ^= ord(char)
    try:
        return checksum == int(expected[:2], 16)
    except ValueError:
        return False
