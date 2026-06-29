
import asyncio
from aiotools import current_taskgroup
import threading
import time
from binascii import unhexlify, hexlify
from collections import deque

from .interface import Interface
from configuration import ConfigView, get_config

from LoRaRF import SX126x, SX127x

import logging
logger = logging.getLogger(__name__)


def _release_reset_pin(pin):
    # Best-effort reset line release for Pi GPIO stacks (RPi.GPIO or rpi-lgpio shim).
    if pin is None or pin < 0:
        return
    try:
        import RPi.GPIO as GPIO
        GPIO.setwarnings(False)
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(pin, GPIO.OUT, initial=GPIO.HIGH)
        time.sleep(0.01)
        GPIO.cleanup(pin)
    except Exception as e:
        logger.debug(f"Could not release reset pin GPIO{pin}: {e}")

# DIO3 TCXO control settings
# SetDio3AsTcxoCtrl
#    DIO3_OUTPUT_1_6                        = 0x00        # DIO3 voltage output for TCXO: 1.6 V
#    DIO3_OUTPUT_1_7                        = 0x01        #                               1.7 V
#    DIO3_OUTPUT_1_8                        = 0x02        #                               1.8 V
#    DIO3_OUTPUT_2_2                        = 0x03        #                               2.2 V
#    DIO3_OUTPUT_2_4                        = 0x04        #                               2.4 V
#    DIO3_OUTPUT_2_7                        = 0x05        #                               2.7 V
#    DIO3_OUTPUT_3_0                        = 0x06        #                               3.0 V
#    DIO3_OUTPUT_3_3                        = 0x07        #                               3.3 V
#    TCXO_DELAY_2_5                         = 0x0140      # TCXO delay time: 2.5 ms
#    TCXO_DELAY_5                           = 0x0280      #                  5 ms
#    TCXO_DELAY_10                          = 0x0560      #                  10 ms

DIO3_VOLTAGE = {
    1.6: 0x00,
    1.7: 0x01,
    1.8: 0x02,
    2.2: 0x03,
    2.4: 0x04,
    2.7: 0x05,
    3.0: 0x06,
    3.3: 0x07
}

TCXO_DELAY = {
    2.5: 0x0140,
    5: 0x0280,
    10: 0x0560
}

class LoRaInterface(Interface):
    """
    Communicate with a directly connected LoRa interface

    """
    def __init__(self, config:ConfigView):
        super().__init__() 

        chip_name = config.get("chip", "sx126x")
        chip = chip_name.lower().replace("-", "")
        chip_aliases = {
            "sx1261": "sx126x",
            "sx1262": "sx126x",
            "sx1268": "sx126x",
            "llcc68": "sx126x",
            "sx126x": "sx126x",
            "sx1272": "sx127x",
            "sx1276": "sx127x",
            "sx1277": "sx127x",
            "sx1278": "sx127x",
            "sx1279": "sx127x",
            "sx127x": "sx127x"
        }
        chip_family = chip_aliases.get(chip, None)

        if chip_family is None:
            raise ValueError(f"Unsupported LoRa chip '{chip_name}'. Supported values: sx126x or sx127x family")

        self.is_sx127x = chip_family == "sx127x"
        self._name = "SX127x device interface" if self.is_sx127x else "SX126x device interface"

        # Flag to signal when data has been transmitted
        self.txdone = asyncio.Event()
        # Last transmit duration (ms)
        self.txtime = 0
        self._last_status = None
        self._tx_wait_since = None
        self._noise_floor_samples = deque(maxlen=16)
        self._noise_floor_estimate_dbm = int(config.get("noise_floor_dbm", -120))

        # Fetch all the config we need
        # Default config is UK/EU Narrow
        if self.is_sx127x:
            # Dragino LoRa/GPS HAT v1.4 defaults (SX1272)
            config.set_default(get_config({
                "chip": "sx1272",
                "frequency": 916575000, "sf": 7, "bw":62500, "cr":8,
                "txpower":17, "airtime": 10,
                "spi":0, "cs": 2, "irq":-1, "reset":22, "txen": -1, "rxen": -1
            }))
        else:
            config.set_default(get_config({
                "chip": "sx1262",
                "frequency": 869618000, "sf": 8, "bw":62500, "cr":8,
                "txpower":22, "airtime": 10,
                # WaveShare SX1262 HAT for Raspberry Pi
                "spi":0, "cs": 0, "irq":16, "busy":20, "reset":18, "txen": 6
            }))

        self.freq = config.get("frequency")
        self.sf = config.get("sf")
        self.bw = config.get("bw")
        self.cr = config.get("cr")
        self.txpower = config.get("txpower")
        airtime = config.get("airtime", 10)
        self.tx_timeout_s = float(config.get("tx_timeout_s", 5.0))
        self.debug = config.get("debug", False)

        spi = config.get("spi")
        cs = config.get("cs")
        irq = config.get("irq")
        self.irq = irq
        busy = config.get("busy")
        reset = config.get("reset")
        txen = config.get("txen", -1)
        rxen = config.get("rxen", -1)
        wake = config.get("wake", -1)

        if self.is_sx127x and reset in (7, 8, 9, 10, 11):
            raise ValueError(
                f"Invalid SX127x reset GPIO{reset}: this pin is reserved for SPI bus signals. "
                "Choose a dedicated GPIO (for Dragino SX1272, use reset=22)."
            )

        dio3_voltage = config.get("dio3.voltage", None)
        dio3_txco_delay = config.get("dio3.tcxo_delay", None)

        dio2_rfswitch = config.get("dio2.rfswitch", False)

        if self.debug:
            logger.warning(
                "LoRa debug enabled: chip=%s spi=%s cs=%s irq=%s reset=%s busy=%s txen=%s rxen=%s wake=%s freq=%s sf=%s bw=%s cr=%s",
                chip_name, spi, cs, irq, reset, busy, txen, rxen, wake, self.freq, self.sf, self.bw, self.cr
            )

        if (dio3_voltage is not None and dio3_txco_delay is None) or (dio3_voltage is None and dio3_txco_delay is not None):
            raise ValueError("Both dio3.voltage and dio3.tcxo_delay must be set to enable DIO3 control")

        try:
            if self.is_sx127x:
                _release_reset_pin(reset)
                self.LoRa = SX127x()
                try:
                    started = self.LoRa.begin(spi, cs, reset, irq, txen, rxen)
                except TypeError:
                    # Compatibility with LoRaRF versions that do not expose txen/rxen in begin().
                    started = self.LoRa.begin(spi, cs, reset, irq)

                # Some LoRaRF builds treat disabled txen/rxen pins poorly when passed as -1.
                # Retry with the plain 4-argument signature before giving up.
                if not started and txen == -1 and rxen == -1:
                    logger.warning("SX127x init failed with txen/rxen disabled; retrying without txen/rxen arguments")
                    started = self.LoRa.begin(spi, cs, reset, irq)

                # Some Pi/GPIO stacks fail to attach IRQ edge detection at init.
                # Retry in polling mode so radio startup still succeeds.
                if not started and irq is not None and irq >= 0:
                    logger.warning(f"SX127x init failed on IRQ GPIO{irq}; retrying with polling (irq=-1)")
                    self.irq = -1
                    try:
                        started = self.LoRa.begin(spi, cs, reset, -1, txen, rxen)
                    except TypeError:
                        started = self.LoRa.begin(spi, cs, reset, -1)

                    if not started and txen == -1 and rxen == -1:
                        logger.warning("SX127x polling init failed with txen/rxen disabled; retrying without txen/rxen arguments")
                        started = self.LoRa.begin(spi, cs, reset, -1)
            else:
                self.LoRa = SX126x()
                started = self.LoRa.begin(spi, cs, reset, busy, irq, txen, rxen, wake)
        except FileNotFoundError as e:
            spidev = f"/dev/spidev{spi}.{cs}"
            raise ValueError(
                f"SPI device {spidev} is not available. "
                "Enable SPI in the OS and verify LoRa interface 'spi'/'cs' config values."
            ) from e

        if not started:
            _release_reset_pin(reset)
            msg = (
                "LoRa interface did not start. "
                f"chip={chip_name} spi={spi} cs={cs} irq={self.irq} reset={reset} "
                f"freq={self.freq} sf={self.sf} bw={self.bw} cr={self.cr}. "
                "Verify spidev node exists, pin mapping, and radio params. "
                "For SX127x on unstable GPIO IRQ systems, set irq=-1."
            )
            logger.error(msg)
            raise ValueError(msg)

        self.LoRa.setFrequency(self.freq)
        if self.is_sx127x:
            self.LoRa.setTxPower(self.txpower, self.LoRa.TX_POWER_PA_BOOST)
            self.LoRa.setRxGain(self.LoRa.RX_GAIN_BOOSTED, self.LoRa.RX_GAIN_AUTO)
            self.max_txpower = 20
        else:
            self.LoRa.setTxPower(self.txpower)
            self.LoRa.setRxGain(self.LoRa.RX_GAIN_BOOSTED)
            self.max_txpower = 27

        # SF, BW, CR, LDRO (low data rate optimization; off)
        self.LoRa.setLoRaModulation(self.sf, self.bw, self.cr, False)

        # DIO3 as TCXO control (optional)
        if self.is_sx127x:
            if dio3_voltage is not None:
                logger.warning("Ignoring dio3.* settings for SX127x interface")
            if dio2_rfswitch:
                logger.warning("Ignoring dio2.rfswitch setting for SX127x interface")
        else:
            if dio3_voltage is not None:
                d3v = DIO3_VOLTAGE.get(dio3_voltage, None)
                d3t = TCXO_DELAY.get(dio3_txco_delay, None)
                if d3v is None or d3t is None:
                    raise ValueError("Invalid dio3.voltage or dio3.tcxo_delay value")

                self.LoRa.setDio3TcxoCtrl(d3v, d3t)

            # DIO2 as RF switch control (optional)
            if dio2_rfswitch:
                self.LoRa.setDio2RfSwitch(True)

        self.LoRa.setLoRaPacket(self.LoRa.HEADER_EXPLICIT, 16, 255, True, False)
        self.LoRa.setSyncWord(0x12)

        self.airtime_dutycycle = airtime     # % duty cycle (default 10%)

        self.airtime_txtimestamp = deque([0,0,0,0,0], maxlen=5)
        self.airtime_txtime = deque([0,0,0,0,0], maxlen=5)

        # SX127x on some Pi GPIO stacks can miss TX_DONE occasionally; allow one
        # automatic retry by default. SX126x keeps retry disabled by default.
        default_tx_retries = 1 if self.is_sx127x else 0
        self.tx_retries = int(config.get("tx_retries", default_tx_retries))

        logger.debug(f"Configured {chip_name} LoRa interface on SPI{spi}:{cs} for {self.freq/1000000:0.3f}MHz, BW: {self.bw/1000}KHz, SF: {self.sf}, CR: {self.cr}")

    def _fallback_to_polling(self):
        # LoRaRF SX127x can fail edge detection on some Pi/GPIO stacks.
        if self.is_sx127x and self.irq is not None and self.irq >= 0:
            logger.warning("SX127x IRQ edge detection failed; falling back to polling mode")
            self.irq = -1
            if hasattr(self.LoRa, "_irq"):
                self.LoRa._irq = None

    def _request_rx_continuous(self):
        try:
            self.LoRa.request(self.LoRa.RX_CONTINUOUS)
        except RuntimeError as e:
            if self.is_sx127x and "edge detection" in str(e).lower():
                self._fallback_to_polling()
                self.LoRa.request(self.LoRa.RX_CONTINUOUS)
            else:
                raise

    # Receive thread
    #
    # FIXME: This thread busywaits on data from the LoRa chip. This could be a setting I've missed,
    # or it might just be how the library works. Either way, it sits there using up an entire core.
    # Need either better config, a better library, or to rewrite the current one so it behaves nicely.
    def rx_thread(self):
        logger.debug("LoRa rx thread listening")

        self._request_rx_continuous()
    
        s = ["STATUS_DEFAULT", "STATUS_TX_WAIT", "STATUS_TX_TIMEOUT", "STATUS_TX_DONE", "STATUS_RX_WAIT", "STATUS_RX_CONTINUOUS", "STATUS_RX_TIMEOUT", "STATUS_RX_DONE", "STATUS_HEADER_ERR", "STATUS_CRC_ERR", "STATUS_CAD_WAIT", "STATUS_CAD_DETECTED", "STATUS_CAD_DONE"]
        while True:
            if self.is_sx127x and self.irq is not None and self.irq < 0:
                # Polling mode: LoRaRF wait() polls IRQ flags via SPI when irq == -1.
                # This updates internal status and RX buffer pointers for status()/available()/read().
                self.LoRa.wait(timeout=0.05)
            else:
                self.LoRa.wait()

            status = self.LoRa.status()
            if status != self._last_status:
                logger.debug(f"Status: {s[status]}")
                self._last_status = status

            if self.is_sx127x and self.irq is not None and self.irq < 0 and status == self.LoRa.STATUS_TX_WAIT:
                now = time.time()
                if self._tx_wait_since is None:
                    self._tx_wait_since = now
                elif now - self._tx_wait_since > 2.0:
                    logger.warning("SX127x stuck in TX_WAIT; forcing RX_CONTINUOUS recovery")
                    self._request_rx_continuous()
                    self._tx_wait_since = None
                continue
            else:
                self._tx_wait_since = None

            if status == self.LoRa.STATUS_RX_DONE:
                logger.debug(f"Packet received, {self.LoRa.available()} bytes")

                data = bytearray()

                while self.LoRa.available():
                    data.append(self.LoRa.read())

                rssi = self.LoRa.packetRssi()
                snr = self.LoRa.snr()

                # Estimate noise floor from received packets: noise ~= RSSI - SNR.
                # Keep a short rolling window so telemetry reflects current RF conditions.
                try:
                    noise_floor = int(round(float(rssi) - float(snr)))
                    self._noise_floor_samples.append(noise_floor)
                    self._noise_floor_estimate_dbm = int(sum(self._noise_floor_samples) / len(self._noise_floor_samples))
                except Exception:
                    pass

                self.eventloop.call_soon_threadsafe(self.rx_q.put_nowait, (data,rssi,snr))
                logger.debug(f"Packet data, {hexlify(data).decode()}")
                if self.is_sx127x and self.irq is not None and self.irq < 0:
                    self._request_rx_continuous()
                continue

            elif status == self.LoRa.STATUS_CRC_ERR:
                logger.info("RX packet CRC error")
                if self.is_sx127x and self.irq is not None and self.irq < 0:
                    self._request_rx_continuous()
                continue
            elif status == self.LoRa.STATUS_HEADER_ERR:
                logger.info("RX packet header error")
                if self.is_sx127x and self.irq is not None and self.irq < 0:
                    self._request_rx_continuous()
                continue

            elif status == self.LoRa.STATUS_TX_DONE:
                self.eventloop.call_soon_threadsafe(self.tx_done, self.LoRa.transmitTime())
                # SX127x behaves better if RX_CONTINUOUS is only requested after TX completes.
                if self.is_sx127x:
                    self._request_rx_continuous()

            # SX126x path expects an explicit re-request after each status transition.
            if not self.is_sx127x:
                self._request_rx_continuous()
            elif self.irq is not None and self.irq < 0 and status in (
                self.LoRa.STATUS_DEFAULT,
                self.LoRa.STATUS_RX_TIMEOUT,
            ):
                # In polling mode, only re-arm on idle/timeout states.
                # Re-requesting during RX_CONTINUOUS can reset demodulation mid-packet.
                self._request_rx_continuous()

    # FIXME race condition here - what is the proper timeout for a transmission?
    def tx_done(self, tx_time):
        self.txtime = tx_time
        self.txdone.set()

    def transmit_wait(self):
        # Based on the last 5 transmissions, are we within the duty cycle limit?
        tx_earliest = self.airtime_txtimestamp[0]

        # How long since the first transmission in the log?
        tx_period = time.time() - tx_earliest
        # Total time (ms)
        tx_total = sum(self.airtime_txtime)
        duty_cycle = 100*(tx_total/1000)/tx_period

        if tx_earliest > 0:
            # We have recorded 5 transmissions
            logger.debug(f"Duty cycle for last {len(self.airtime_txtimestamp)} transmissions: {duty_cycle:0.2f}%")

        # Sleep until the duty cycle would be less than 10% (or whatever airtime_dutycycle is)
        # Rather than wait until we hit the duty cycle limit and then sleep, if the duty cycle is half
        # the limit (eg, 5%), sleep for half the required time. If it's a quarter, sleep for 25% of the
        # required time. This will have the effect of spreading out the wait periods, rather than
        # transmitting a bunch of packets then a long pause
        for c in range(3):
            fraction = 1/(1<<c)     # 1/1, 1/2, 1/4
            airtime_dutycycle = self.airtime_dutycycle * fraction

            if duty_cycle > airtime_dutycycle:
                tx_min = (tx_earliest + (tx_total/1000)/(airtime_dutycycle / 100) - time.time()) * fraction

                if tx_min>0:
                    logger.debug(f"Sleep for {tx_min:0.2f} seconds for duty cycle compliance ({airtime_dutycycle}%)")
                    return tx_min

        return 0

    async def transmit(self, packetdata):
        logger.debug(f"Transmitting: {hexlify(packetdata).decode()}")

        attempts = max(1, self.tx_retries + 1)
        for attempt in range(1, attempts + 1):
            self.txdone.clear()
            self.txtime = 0

            self.LoRa.beginPacket()
            self.LoRa.put(packetdata)
            try:
                self.LoRa.endPacket()
            except RuntimeError as e:
                if self.is_sx127x and "edge detection" in str(e).lower():
                    self._fallback_to_polling()
                    self.LoRa.endPacket()
                else:
                    raise

            try:
                await asyncio.wait_for(self.txdone.wait(), self.tx_timeout_s)

                logger.debug("Transmit time: {0:0.2f} ms".format(self.txtime))

                self.airtime_txtimestamp.append(time.time())
                self.airtime_txtime.append(self.txtime)
                self.txdone.clear()
                return self.txtime

            except TimeoutError:
                logger.warning(f"Transmit timed out (attempt {attempt}/{attempts})")
                # SX127x can stall in TX_WAIT on some GPIO/IRQ stacks. Recover by
                # forcing polling mode and re-arming RX_CONTINUOUS.
                if self.is_sx127x:
                    try:
                        self._fallback_to_polling()
                        self._request_rx_continuous()
                        logger.warning("SX127x TX timeout recovery applied (polling RX re-arm)")
                    except Exception as e:
                        logger.warning(f"Failed to recover after TX timeout: {e}")

                if attempt < attempts:
                    await asyncio.sleep(0.05)
                    logger.warning(f"Retrying TX (attempt {attempt + 1}/{attempts})")

        self.txdone.clear()
        return self.txtime

    # Return a tuple containing frequency (kHz), bandwidth (Hz), spreading factor, coding rate,
    # tx power (dBm), maximum tx power (dBm)
    def get_radioconfig(self):
        return (self.freq//1000, self.bw, self.sf, self.cr, self.txpower, self.max_txpower)

    def noisefloordbm(self):
        return self._noise_floor_estimate_dbm

    async def start(self):
        self.eventloop = asyncio.get_running_loop()
        # Start the receiver in its own thread as it's not asynchronous, make it a daemon thread so it
        # doesn't stop the program terminating
        self.rxthread = threading.Thread(target=self.rx_thread, daemon=True)
        self.rxthread.start()
