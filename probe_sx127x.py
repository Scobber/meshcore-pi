#!/usr/bin/env python3
"""
Minimal SX127x probe for Raspberry Pi.

Reads the SX127x version register (0x42) over spidev to confirm that
SPI wiring and chip-select are correct before running meshcore.
"""

import argparse
import sys
import time


def _reset_radio(reset_pin: int) -> None:
    try:
        import RPi.GPIO as gpio
    except Exception as exc:
        print(f"WARN: reset requested but RPi.GPIO is unavailable: {exc}")
        return

    gpio.setwarnings(False)
    gpio.setmode(gpio.BCM)
    gpio.setup(reset_pin, gpio.OUT, initial=gpio.HIGH)
    gpio.output(reset_pin, gpio.LOW)
    time.sleep(0.001)
    gpio.output(reset_pin, gpio.HIGH)
    time.sleep(0.005)
    gpio.cleanup(reset_pin)


def _read_reg(spi, addr: int) -> int:
    # MSB=0 for read operation on SX127x.
    resp = spi.xfer2([addr & 0x7F, 0x00])
    return int(resp[1])


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe SX127x via spidev")
    parser.add_argument("--spi", type=int, default=0, help="SPI bus (default: 0)")
    parser.add_argument("--cs", type=int, default=0, help="SPI chip-select (default: 0)")
    parser.add_argument("--reset", type=int, default=None, help="Optional BCM reset pin")
    parser.add_argument("--speed", type=int, default=5_000_000, help="SPI speed in Hz (default: 5000000)")
    parser.add_argument("--tries", type=int, default=5, help="Version read attempts (default: 5)")
    args = parser.parse_args()

    try:
        import spidev
    except Exception as exc:
        print(f"ERROR: spidev module not available: {exc}")
        return 2

    dev = f"/dev/spidev{args.spi}.{args.cs}"
    print(f"Probing {dev} ...")

    if args.reset is not None:
        print(f"Toggling reset pin BCM{args.reset}")
        _reset_radio(args.reset)

    spi = spidev.SpiDev()
    try:
        spi.open(args.spi, args.cs)
    except FileNotFoundError:
        print(f"ERROR: {dev} does not exist. Enable SPI and verify bus/cs.")
        return 3
    except PermissionError:
        print(f"ERROR: permission denied opening {dev}. Add user to spi group or run with sudo.")
        return 4
    except Exception as exc:
        print(f"ERROR: failed to open {dev}: {exc}")
        return 5

    spi.max_speed_hz = args.speed
    spi.mode = 0

    versions = []
    try:
        for _ in range(max(1, args.tries)):
            versions.append(_read_reg(spi, 0x42))
            time.sleep(0.02)
    finally:
        spi.close()

    hex_versions = ", ".join(f"0x{v:02X}" for v in versions)
    print(f"Version reads: {hex_versions}")

    good = any(v in (0x12, 0x22) for v in versions)
    if good:
        print("OK: SX127x detected (expected version 0x12 or 0x22).")
        return 0

    if all(v == 0x00 for v in versions):
        print("FAIL: all zeros. Typical causes: reset held low, power issue, or wrong wiring.")
    elif all(v == 0xFF for v in versions):
        print("FAIL: all 0xFF. Typical causes: no device on selected CS or floating MISO.")
    else:
        print("FAIL: unexpected version values. Check bus/cs/reset mapping and SPI mode/speed.")

    return 1


if __name__ == "__main__":
    sys.exit(main())
