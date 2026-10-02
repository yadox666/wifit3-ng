"""Cross-platform receive-only HackRF sweep over PyUSB."""
from __future__ import annotations

import asyncio
import errno
import math
import struct
import sys
from dataclasses import dataclass
from typing import Callable

import libusb_package
import numpy as np
import usb.core
import usb.util

from wifit3.sdr.hackrf import HackRfDevice, find_hackrf_devices

_REQUEST_TYPE_OUT = 0x40
_REQUEST_TYPE_IN = 0xC0
_SET_TRANSCEIVER_MODE = 1
_SAMPLE_RATE_SET = 6
_BASEBAND_FILTER_BANDWIDTH_SET = 7
_SET_FREQ = 16
_AMP_ENABLE = 17
_SET_LNA_GAIN = 19
_SET_VGA_GAIN = 20
_TRANSCEIVER_OFF = 0
_TRANSCEIVER_RECEIVE = 1
_RX_ENDPOINT = 0x81
_TRANSFER_SIZE = 262_144
_SAMPLE_RATE_HZ = 20_000_000
_USABLE_HALF_BAND_MHZ = 8
_FFT_SIZE = 32_768
HACKRF_LNA_GAINS = tuple(range(0, 41, 8))
HACKRF_VGA_GAINS = tuple(range(0, 63, 2))


@dataclass(frozen=True, slots=True)
class SpectrumPoint:
    frequency_hz: float
    power_dbfs: float


class HackRfSweepError(RuntimeError):
    pass


class HackRfSweep:
    """Tune, receive IQ, and calculate FFT bins without OS-specific HackRF tools."""

    def __init__(
        self,
        on_points: Callable[[list[SpectrumPoint]], None],
        on_error: Callable[[str], None],
        device: HackRfDevice | None = None,
    ) -> None:
        self._on_points = on_points
        self._on_error = on_error
        self._selected_device = device
        self._usb_device = None
        self._interface_number = 0
        self._detached_kernel_driver = False
        self._task: asyncio.Task | None = None
        self._stopping = False
        self._start_mhz = 0
        self._stop_mhz = 0
        self._bin_width_hz = 1_000_000
        self._lna_gain = 16
        self._vga_gain = 20
        self._applied_gains: tuple[int, int] | None = None
        self._clip_ratio = 0.0

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def clip_ratio(self) -> float:
        return self._clip_ratio

    def set_gains(self, lna_gain: int, vga_gain: int) -> None:
        if lna_gain not in HACKRF_LNA_GAINS:
            raise ValueError(f"Invalid HackRF LNA gain: {lna_gain}")
        if vga_gain not in HACKRF_VGA_GAINS:
            raise ValueError(f"Invalid HackRF VGA gain: {vga_gain}")
        self._lna_gain = lna_gain
        self._vga_gain = vga_gain

    async def start(
        self,
        start_mhz: int,
        stop_mhz: int,
        *,
        bin_width_hz: int = 1_000_000,
        lna_gain: int = 16,
        vga_gain: int = 20,
    ) -> None:
        await self.stop()
        if start_mhz >= stop_mhz:
            raise HackRfSweepError("Invalid spectrum range")
        self.set_gains(lna_gain, vga_gain)
        devices = find_hackrf_devices()
        selected = self._selected_device
        if selected is not None and not any(
            device.instance_key == selected.instance_key for device in devices
        ):
            selected = None
        if selected is None:
            selected = devices[0] if devices else None
        if selected is None:
            raise HackRfSweepError("HackRF One was disconnected")
        self._selected_device = selected
        self._start_mhz = start_mhz
        self._stop_mhz = stop_mhz
        self._bin_width_hz = max(100_000, bin_width_hz)
        self._clip_ratio = 0.0
        self._applied_gains = None
        self._stopping = False
        try:
            await asyncio.to_thread(self._open, selected)
        except Exception as exc:
            await asyncio.to_thread(self._close)
            if isinstance(exc, HackRfSweepError):
                raise
            raise HackRfSweepError(f"Could not open HackRF: {exc}") from exc
        self._task = asyncio.create_task(self._sweep_loop())

    async def stop(self) -> None:
        self._stopping = True
        task, self._task = self._task, None
        if task is not None and task is not asyncio.current_task():
            await task
        elif self._usb_device is not None:
            await asyncio.to_thread(self._close)

    async def _sweep_loop(self) -> None:
        try:
            while not self._stopping:
                for center_mhz in self._centers():
                    if self._stopping:
                        break
                    points = await asyncio.to_thread(self._capture_tile, center_mhz)
                    self._on_points(points)
                await asyncio.sleep(0)
        except usb.core.USBError as exc:
            if not self._stopping and getattr(exc, "errno", None) in (errno.EIO, 60, 110):
                self._on_error("HackRF USB endpoint stopped responding; replug the device")
            elif not self._stopping:
                self._on_error(f"HackRF receive failed: {exc}")
        except Exception as exc:
            if not self._stopping:
                self._on_error(f"HackRF receive failed: {exc}")
        finally:
            await asyncio.to_thread(self._close)

    def _centers(self) -> list[float]:
        width = self._stop_mhz - self._start_mhz
        if width <= 2 * _USABLE_HALF_BAND_MHZ:
            return [(self._start_mhz + self._stop_mhz) / 2]
        first = self._start_mhz + _USABLE_HALF_BAND_MHZ
        last = self._stop_mhz - _USABLE_HALF_BAND_MHZ
        centers = []
        center = first
        while center < last:
            centers.append(center)
            center += 2 * _USABLE_HALF_BAND_MHZ
        if not centers or not math.isclose(centers[-1], last):
            centers.append(last)
        return centers

    def _open(self, selected: HackRfDevice) -> None:
        backend = libusb_package.get_libusb1_backend()
        device = usb.core.find(
            idVendor=selected.vid,
            idProduct=selected.pid,
            bus=selected.bus,
            address=selected.address,
            backend=backend,
        )
        if device is None:
            raise HackRfSweepError("HackRF One was disconnected")
        self._usb_device = device
        try:
            try:
                device.get_active_configuration()
            except usb.core.USBError:
                device.set_configuration()
            if sys.platform != "darwin":
                try:
                    if device.is_kernel_driver_active(self._interface_number):
                        device.detach_kernel_driver(self._interface_number)
                        self._detached_kernel_driver = True
                except (AttributeError, NotImplementedError):
                    pass
            usb.util.claim_interface(device, self._interface_number)
            self._control_out(_SAMPLE_RATE_SET, data=struct.pack("<II", _SAMPLE_RATE_HZ, 1))
            self._control_out(
                _BASEBAND_FILTER_BANDWIDTH_SET,
                value=15_000_000 & 0xFFFF,
                index=15_000_000 >> 16,
            )
            self._control_out(_AMP_ENABLE, value=0)
            self._apply_gains()
            self._control_out(_SET_TRANSCEIVER_MODE, value=_TRANSCEIVER_RECEIVE)
        except usb.core.USBError as exc:
            if getattr(exc, "errno", None) in (errno.EACCES, errno.EPERM):
                raise HackRfSweepError("USB access denied") from exc
            if getattr(exc, "errno", None) in (errno.EIO, 60, 110):
                raise HackRfSweepError(
                    "HackRF USB endpoint stopped responding; replug the device",
                ) from exc
            raise HackRfSweepError(str(exc)) from exc

    def _capture_tile(self, center_mhz: float) -> list[SpectrumPoint]:
        self._apply_gains()
        whole_mhz = int(center_mhz)
        remainder_hz = round((center_mhz - whole_mhz) * 1_000_000)
        self._control_out(
            _SET_FREQ,
            data=struct.pack("<II", whole_mhz, remainder_hz),
        )
        self._read_iq()
        samples = self._read_iq()
        return self._power_bins(samples, center_mhz * 1_000_000)

    def _read_iq(self) -> np.ndarray:
        if self._usb_device is None:
            raise HackRfSweepError("HackRF is not open")
        raw = bytes(self._usb_device.read(_RX_ENDPOINT, _TRANSFER_SIZE, timeout=1000))
        values = np.frombuffer(raw, dtype=np.int8)
        self._clip_ratio = float(np.mean((values <= -127) | (values >= 126)))
        sample_count = min(_FFT_SIZE, len(values) // 2)
        if sample_count < 1024:
            raise HackRfSweepError("HackRF returned too few IQ samples")
        i_values = values[:sample_count * 2:2].astype(np.float32)
        q_values = values[1:sample_count * 2:2].astype(np.float32)
        return (i_values + 1j * q_values) / 128.0

    def _power_bins(self, samples: np.ndarray, center_hz: float) -> list[SpectrumPoint]:
        samples = samples - np.mean(samples)
        window = np.hanning(len(samples))
        transformed = np.fft.fftshift(np.fft.fft(samples * window))
        power = 20 * np.log10(np.maximum(np.abs(transformed) / window.sum(), 1e-12))
        offsets = np.fft.fftshift(
            np.fft.fftfreq(len(samples), d=1 / _SAMPLE_RATE_HZ),
        )
        power[np.abs(offsets) < 250_000] = -240
        frequencies = center_hz + offsets
        usable = np.abs(frequencies - center_hz) <= _USABLE_HALF_BAND_MHZ * 1_000_000
        frequencies = frequencies[usable]
        power = power[usable]
        first_bin = math.floor(frequencies[0] / self._bin_width_hz)
        last_bin = math.floor(frequencies[-1] / self._bin_width_hz)
        points = []
        for bin_index in range(first_bin, last_bin + 1):
            low_hz = bin_index * self._bin_width_hz
            selected = (frequencies >= low_hz) & (
                frequencies < low_hz + self._bin_width_hz
            )
            if not np.any(selected):
                continue
            frequency_hz = low_hz + self._bin_width_hz / 2
            if not self._start_mhz * 1_000_000 <= frequency_hz <= self._stop_mhz * 1_000_000:
                continue
            points.append(SpectrumPoint(
                frequency_hz,
                float(np.max(power[selected])),
            ))
        return points

    def _control_out(
        self,
        request: int,
        *,
        value: int = 0,
        index: int = 0,
        data: bytes | None = None,
    ) -> None:
        if self._usb_device is None:
            raise HackRfSweepError("HackRF is not open")
        payload = data if data is not None else None
        result = self._usb_device.ctrl_transfer(
            _REQUEST_TYPE_OUT,
            request,
            value,
            index,
            payload,
            timeout=1000,
        )
        expected = len(data) if data is not None else 0
        if result != expected:
            raise HackRfSweepError(f"HackRF rejected USB request {request}")

    def _set_gain(self, request: int, value: int) -> None:
        if self._usb_device is None:
            raise HackRfSweepError("HackRF is not open")
        result = bytes(self._usb_device.ctrl_transfer(
            _REQUEST_TYPE_IN,
            request,
            0,
            value,
            1,
            timeout=1000,
        ))
        if result != b"\x01":
            raise HackRfSweepError(f"HackRF rejected gain request {request}")

    def _apply_gains(self) -> None:
        gains = (self._lna_gain, self._vga_gain)
        if self._applied_gains == gains:
            return
        self._set_gain(_SET_LNA_GAIN, self._lna_gain)
        self._set_gain(_SET_VGA_GAIN, self._vga_gain)
        self._applied_gains = gains

    def _close(self) -> None:
        device, self._usb_device = self._usb_device, None
        if device is None:
            return
        try:
            device.ctrl_transfer(
                _REQUEST_TYPE_OUT,
                _SET_TRANSCEIVER_MODE,
                _TRANSCEIVER_OFF,
                0,
                None,
                timeout=1000,
            )
        except Exception:
            pass
        try:
            usb.util.release_interface(device, self._interface_number)
        except Exception:
            pass
        if self._detached_kernel_driver:
            try:
                device.attach_kernel_driver(self._interface_number)
            except Exception:
                pass
        self._detached_kernel_driver = False
        self._applied_gains = None
        usb.util.dispose_resources(device)
