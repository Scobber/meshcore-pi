
# Common device type for repeaters, room servers and other things with a CLI

import asyncio
from aiotools import current_taskgroup
import ast
import re
from collections import Counter

import struct
import time
from random import randbytes
from binascii import unhexlify, hexlify

from dispatch import Dispatch
from exceptions import *
import packet
from identity import AnonIdentity, Identity, IdentityStore, AdvertType
from ed25519_wrapper import ED25519_Wrapper
from misc import unique_time, validate_latlon
from basicmesh import BasicMesh

import logging

logger = logging.getLogger(__name__)

class CLIDevice(BasicMesh):
    """
    Mesh for a device with the following characteristics:
     * CLI interface for configuration
     * Anonymous requests
    ie, a repeater or room server
    """
    def __init__(self, me, neighbour_ids, dispatcher, hardware, config):
        # Store of identities which have logged in
        # This doesn't need to be stored to disk, as it's just a cache of currently logged in users
        logged_in_ids = IdentityStore()

        super().__init__(me, logged_in_ids, None, dispatcher)

        # Neighbour identities - used for keeping track of neighbouring routers
        # In Meshcore, this is for repeaters only, but room servers can also have neighbours
        self.neighbour_ids = neighbour_ids

        # What time we started (in order to calculate device uptime)
        self.begintime = time.time()

        self.hardware = hardware

        # Additional configuration
        self.config = config

        self.flood_interval = 0
        self.last_flood_advert = 0

        self.direct_interval = 0
        self.last_direct_advert = 0

        self.log_enabled = bool(self.config.get('log.enabled', False))
        self.log_buffer = []
        self.log_buffer_max = 200

    # Send adverts periodically
    # Flood adverts are sent every 3 hours (default, configurable); direct adverts every 90 minutes (same).
    # Don't send a direct advert if we sent a flood advert in the last 2 minutes, or will do in the next 2.
    # This is to avoid sending two adverts in quick succession.
    async def tx_advert_flood(self):

        # Interval between flood adverts, -1 = disabled, 0 = once only on startup, >0 = repeat in hours
        flood_interval = self.config.get('advert.flood', -1)
        if flood_interval >= 0:
            self.flood_interval = flood_interval * 60 * 60
        else:
            # Disabled
            self.flood_interval = 0
            logger.debug("Flood adverts disabled")
            return

        while True:
            await self.tx_advert(flood=True, priority=Dispatch.PRIORITY_SCHEDULED_ADVERT)
            self.last_flood_advert = time.time()
            logger.debug("Scheduled flood advert sent")

            if self.flood_interval == 0:
                # Only once
                break

            await asyncio.sleep(self.flood_interval)

        logger.debug("Exiting flood advert task")


    async def tx_advert_direct(self):
        # Interval between direct adverts, -1 = disabled, 0 = once only on startup, >0 = repeat in minutes
        direct_interval = self.config.get('advert.direct', 0)
        if direct_interval >= 0:
            self.direct_interval = direct_interval * 60
        else:
            # Disabled
            self.direct_interval = 0
            logger.debug("Direct adverts disabled")
            return

        # Sleep for 2 seconds to allow flood advert to be sent first if both are enabled
        await asyncio.sleep(2)

        while True:
            # Don't send a direct advert if we sent a flood advert in the last 2 minutes,
            # or will do in the next 2 minutes
            now = time.time()
            next_flood = self.last_flood_advert + self.flood_interval

            if (self.last_flood_advert + 120) > now or (        # within 2 minutes of last flood advert; or
                (next_flood > now) and      # next flood is in the future and
                ((next_flood - 120) < now) or ( # less than 2 minutes away; or
                (next_flood < now) and self.flood_interval > 0) # next flood is in the past,
                                                                # but floods are on, so the next one is immediately imminent
                ):
                logger.debug("Skipping scheduled direct advert to avoid clash with scheduled flood advert")
            else:
                await self.tx_advert(flood=False, priority=Dispatch.PRIORITY_SCHEDULED_ADVERT)
                logger.debug("Scheduled direct advert sent")

            if self.direct_interval == 0:
                # Only once
                break

            await asyncio.sleep(self.direct_interval)

        logger.debug("Exiting direct advert task")


    # Advert received; log it as a neighbour if it's a zero-hop repeater advert
    async def rx_advert(self, rx_packet:packet.MC_Advert):
        if rx_packet.advert.adv_type != AdvertType.REPEATER:
            logger.debug("Non-repeater advert ignored")
            return

        # Only add zero-hop adverts
        if rx_packet.pathlen != 0:
            logger.debug("Non-zero hop advert ignored")
            return

        id = Identity(rx_packet.advert, advertpath=rx_packet.path)
        id.snr = rx_packet.snr
        id.rssi = rx_packet.rssi
        # Path signal params are carried in advert path bytes for multi-hop adverts.
        # Zero-hop adverts have no hop bytes, but keep the field for consistent output.
        id.path_signal_params = bytes(rx_packet.path)

        # Don't need to bother with a shared secret, we won't be sending anything to this identity

        result = self.neighbour_ids.add_identity(id)
        if result:
            logger.debug(f"Zero-hop repeater neighbour added, {id.name} {hexlify(id.pubkey).decode('utf8')}")


    def neighbours(self):
        """
        Return up to 8 neighbours, in a compact format suitable for one Meshcore packet
        """
        neighbours = self.neighbour_ids.get_all()
        # Returned data is neighbour ID (4 bytes of pubkey), seconds since last heard, last SNR
        # Store here as seconds,SNR,pubkey, so the most recent come out first in a sort
        now = int(time.time())

        n_list = [ (now - n.rxtime, int((n.snr or 0)*4) & 0xff, n.pubkey[0:4]) for n in neighbours ]

        response = ""

        count = None

        for count, neighbour in enumerate(sorted(n_list)):
            if count>0:
                response += "\n"
            response += f"{hexlify(neighbour[2]).decode()}:{neighbour[0]}:{neighbour[1]}"

            if count>6:
                # count=7, which means 8 entries
                break
        else:
            # Didn't break out. Did we do any?
            if count is None:
                response = "-none-"

        return response

    def zero_hop_neighbours(self):
        """
        Return the zero-hop neighbour list.
        Neighbours are only populated from zero-hop repeater adverts.
        """
        neighbours = self.neighbour_ids.get_all()
        now = int(time.time())

        rows = []
        for n in neighbours:
            age = now - n.rxtime
            snr_qdb = int(round((n.snr or 0) * 4))
            rssi_dbm = int(round(n.rssi or 0))
            pathsig = hexlify(getattr(n, 'path_signal_params', b'')).decode()
            rows.append((age, n.pubkey[0:4], snr_qdb, rssi_dbm, pathsig))

        if not rows:
            return "-none-"

        response = ""
        for idx, row in enumerate(sorted(rows)):
            if idx > 0:
                response += "\n"
            response += f"{hexlify(row[1]).decode()}:{row[0]}:{row[2]}:{row[3]}:{row[4]}"

            if idx > 6:
                break

        return response

    # Settings exposed by repeater/CLI admin options
    _admin_setting_specs = {
        'advert.direct': {'type': int},
        'advert.flood': {'type': int},
        'admin.password': {'type': str},
        'admin.keys': {'type': list, 'fallback': ['admin.pubkeys']},
        'guest.open': {'type': bool},
        'guest.password': {'type': str},
        'guest.keys': {'type': list, 'fallback': ['guest.pubkeys']},
    }

    _admin_setting_aliases = {
        'direct': 'advert.direct',
        'advertdirect': 'advert.direct',
        'directadvert': 'advert.direct',
        'advert.direct': 'advert.direct',

        'flood': 'advert.flood',
        'advertflood': 'advert.flood',
        'floodadvert': 'advert.flood',
        'advert.flood': 'advert.flood',

        'adminpassword': 'admin.password',
        'admin.password': 'admin.password',

        'adminkeys': 'admin.keys',
        'adminpubkeys': 'admin.keys',
        'admin.keys': 'admin.keys',
        'admin.pubkeys': 'admin.keys',

        'guestopen': 'guest.open',
        'guest.open': 'guest.open',

        'guestpassword': 'guest.password',
        'guest.password': 'guest.password',

        'guestkeys': 'guest.keys',
        'guestpubkeys': 'guest.keys',
        'guest.keys': 'guest.keys',
        'guest.pubkeys': 'guest.keys',
    }

    _radio_setting_aliases = {
        'frequency': 'frequency',
        'freq': 'frequency',
        'radiofrequency': 'frequency',
        'radiofreq': 'frequency',
        'radio.frequency': 'frequency',

        'bandwidth': 'bandwidth',
        'band': 'bandwidth',
        'bandwith': 'bandwidth',
        'bw': 'bandwidth',
        'radiobandwidth': 'bandwidth',
        'radiobw': 'bandwidth',
        'radio.bandwidth': 'bandwidth',

        'spreadfactor': 'spreading_factor',
        'spreadingfactor': 'spreading_factor',
        'spreading': 'spreading_factor',
        'sf': 'spreading_factor',
        'radio.sf': 'spreading_factor',

        'codingrate': 'coding_rate',
        'coderate': 'coding_rate',
        'coding': 'coding_rate',
        'cr': 'coding_rate',
        'radio.cr': 'coding_rate',

        'tx': 'tx_power',
        'txpower': 'tx_power',
        'radio.tx': 'tx_power',
        'radio.txpower': 'tx_power',

        'rxgain': 'rx_gain',
        'radiorxgain': 'rx_gain',
        'radio.rxgain': 'rx_gain',

        'region': 'region',
        'radioregion': 'region',
        'radio.region': 'region',

        'regions': 'regions',
        'regionlist': 'regions',
        'radio.regions': 'regions',

        'radioconfig': 'all',
        'radiosettings': 'all',
        'radio': 'all',
    }

    _supported_regions = [
        'EU868', 'US915', 'AU915', 'AS923', 'IN865', 'KR920', 'RU864',
        'CN470', 'CN779', 'EU433',
    ]

    _owner_setting_aliases = {
        'owner': 'all',
        'ownerinfo': 'all',
        'ownerdetails': 'all',

        'name': 'name',
        'ownername': 'name',
        'owner.name': 'name',

        'lat': 'lat',
        'latitude': 'lat',
        'ownerlat': 'lat',
        'owner.lat': 'lat',
        'owner.latitude': 'lat',

        'lon': 'lon',
        'long': 'lon',
        'longitude': 'lon',
        'ownerlon': 'lon',
        'owner.lon': 'lon',
        'owner.longitude': 'lon',

        'latlon': 'latlon',
        'location': 'latlon',
        'ownerlocation': 'latlon',
        'owner.latlon': 'latlon',
    }

    def _normalise_admin_setting(self, name):
        setting = name.strip().lower().replace('_', '').replace('-', '').replace(' ', '').replace('.', '')
        return self._admin_setting_aliases.get(setting)

    def _normalise_radio_setting(self, name):
        setting = name.strip().lower().replace('_', '').replace('-', '').replace(' ', '').replace('.', '')
        return self._radio_setting_aliases.get(setting)

    def _normalise_owner_setting(self, name):
        setting = name.strip().lower().replace('_', '').replace('-', '').replace(' ', '').replace('.', '')
        return self._owner_setting_aliases.get(setting)

    def _canonicalise_command_text(self, command_text):
        # Companion app may send spaced names; normalise those to existing aliases.
        command_text = re.sub(r'^\s*(get|show|set)\s+owner\s+info\b', r'\1 ownerinfo', command_text, flags=re.IGNORECASE)
        command_text = re.sub(r'^\s*(get|show|set)\s+radio\s+settings\b', r'\1 radiosettings', command_text, flags=re.IGNORECASE)
        command_text = re.sub(r'^\s*owner\s+info\b', 'ownerinfo', command_text, flags=re.IGNORECASE)
        command_text = re.sub(r'^\s*radio\s+settings\b', 'radiosettings', command_text, flags=re.IGNORECASE)
        return command_text.strip()

    def _normalise_flag_value(self, value):
        lowered = value.strip().lower()
        if lowered in ('1', 'on', 'true', 'yes', 'enabled'):
            return True
        if lowered in ('0', 'off', 'false', 'no', 'disabled'):
            return False
        raise ValueError("Expected on|off")

    def _format_on_off(self, value):
        return 'on' if bool(value) else 'off'

    def _record_log(self, line):
        if not self.log_enabled:
            return

        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        self.log_buffer.append(f"{stamp} {line}")
        if len(self.log_buffer) > self.log_buffer_max:
            self.log_buffer = self.log_buffer[-self.log_buffer_max:]

    def _normalise_freq_hz(self, value):
        freq = float(value)
        # CLI command expects MHz. Keep compatibility with kHz/Hz values too.
        if freq < 10000:
            return int(round(freq * 1000000.0))
        if freq < 10000000:
            return int(round(freq * 1000.0))
        return int(round(freq))

    def _normalise_bw_hz(self, value):
        bw = float(value)
        # Most CLI flows use kHz for bandwidth input.
        if bw < 1000:
            return int(round(bw * 1000.0))
        return int(round(bw))

    def _board_command(self):
        board_name = self.hardware.__class__.__name__
        return f"meshcore-pi,{self.internalname},{board_name}"

    def _stats_core_command(self):
        stats = self.get_stats()
        fields = [
            f"uptime={stats.get('uptime', 0)}",
            f"received={stats.get('received', 0)}",
            f"sent={stats.get('sent', 0)}",
            f"badpacket={stats.get('badpacket', 0)}",
            f"neighbours={stats.get('neighbours', 0)}",
        ]
        return "\n".join(fields)

    def _stats_radio_command(self):
        radio = self._radio_config_map()
        noise_floor = self._noise_floor_dbm()
        return "\n".join([
            f"freq_mhz={radio['frequency'] / 1000.0:.3f}",
            f"bw_khz={radio['bandwidth'] / 1000.0:g}",
            f"sf={radio['spreading_factor']}",
            f"cr={radio['coding_rate']}",
            f"tx={radio['tx_power']}",
            f"txmax={radio['tx_power_max']}",
            f"rxgain={self._format_on_off(radio['rx_gain'])}",
            f"noise_floor_dbm={noise_floor}",
            f"airtime={int(self.dispatch.airtime)}",
        ])

    def _noise_floor_dbm(self):
        # Prefer radio-interface measurements when available.
        for iface in self.dispatch.interfaces:
            provider = getattr(iface, 'noisefloordbm', None)
            if not callable(provider):
                continue
            try:
                value = int(provider())
                break
            except Exception:
                value = None
        else:
            value = None

        # Fall back to hardware provider if interface does not supply it.
        provider = getattr(self.hardware, 'noisefloordbm', None)
        if value is None and callable(provider):
            try:
                value = int(provider())
            except Exception:
                value = int(self.config.get('telemetry.noise_floor_dbm', self.config.get('radio.noise_floor_dbm', -120)))

        if value is None:
            value = int(self.config.get('telemetry.noise_floor_dbm', self.config.get('radio.noise_floor_dbm', -120)))

        if value < -32768:
            return -32768
        if value > 32767:
            return 32767
        return value

    def _stats_packets_command(self):
        interesting = []
        for key in sorted(self.stats.keys()):
            if key == 'sent' or key == 'received' or key.startswith('sent.') or key.startswith('received.') or key.startswith('repeat.') or key.startswith('duplicate.'):
                interesting.append(f"{key}={self.stats[key]}")

        if not interesting:
            return "sent=0\nreceived=0"

        return "\n".join(interesting)

    def _clear_stats_command(self):
        self.stats = Counter()
        return "OK - stats cleared"

    def _log_command(self, action=None):
        if action == 'start':
            self.log_enabled = True
            self.config.set('log.enabled', True, save=True)
            return "OK - log started"

        if action == 'stop':
            self.log_enabled = False
            self.config.set('log.enabled', False, save=True)
            return "OK - log stopped"

        if action == 'erase':
            self.log_buffer = []
            return "OK - log erased"

        if not self.log_buffer:
            return "-empty-"

        return "\n".join(self.log_buffer[-50:])

    def _get_private_key(self):
        return hexlify(self.me.private_key.meshcore_private_key).decode('utf8')

    def _set_private_key(self, value):
        key_hex = value.strip().lower()
        raw = unhexlify(key_hex)
        if len(raw) != 64:
            raise ValueError("Private key must be 64 bytes (128 hex chars)")

        wrapper = ED25519_Wrapper(raw)
        self.me.private_key = wrapper
        self.me._identity = wrapper.public_key
        self.config.set('privatekey', key_hex, save=True)
        return "OK - private key updated"

    def _owner_latlon(self):
        if self.me.latlon is not None:
            return self.me.latlon

        lat = self.config.get('lat')
        lon = self.config.get('lon')
        if lat is None or lon is None:
            return None

        try:
            return validate_latlon(lat, lon)
        except ValueError:
            return None

    def _owner_get_command(self, name):
        setting = self._normalise_owner_setting(name)
        if setting is None:
            return None

        owner_name = self.me.name.decode(errors='replace') if self.me.name is not None else ""
        latlon = self._owner_latlon()
        lat = None if latlon is None else latlon[0]
        lon = None if latlon is None else latlon[1]

        if setting == 'all':
            # Keep this parse-friendly for the companion app: name,lat,lon
            return f"{owner_name},{'' if lat is None else lat},{'' if lon is None else lon}"

        if setting == 'name':
            return owner_name
        if setting == 'lat':
            return '(unset)' if lat is None else str(lat)
        if setting == 'lon':
            return '(unset)' if lon is None else str(lon)
        if setting == 'latlon':
            if lat is None or lon is None:
                return "(unset)"
            return f"{lat},{lon}"

        return None

    def _owner_set_name(self, value):
        new_name = value.strip()
        self.me.name = new_name

        changed = self.config.set('name', new_name, save=True)
        if changed:
            return f"OK - owner.name={new_name}"

        return "OK - owner.name unchanged"

    def _owner_set_latlon(self, lat, lon):
        lat, lon = validate_latlon(lat, lon)

        changed_lat = self.config.set('lat', lat, save=False)
        changed_lon = self.config.set('lon', lon, save=False)
        self.me.latlon = (lat, lon)

        if changed_lat or changed_lon:
            self.config.save()
            return f"OK - owner.lat={lat} owner.lon={lon}"

        return "OK - owner.latlon unchanged"

    def _owner_set_single_coord(self, setting, value):
        coord_value = float(value.strip())

        if setting == 'lat':
            lat = coord_value
            lon = self.config.get('lon')
            if lon is None and self.me.latlon is not None:
                lon = self.me.latlon[1]
            changed = self.config.set('lat', lat, save=True)
        else:
            lon = coord_value
            lat = self.config.get('lat')
            if lat is None and self.me.latlon is not None:
                lat = self.me.latlon[0]
            changed = self.config.set('lon', lon, save=True)

        if lat is not None and lon is not None:
            self.me.latlon = validate_latlon(lat, lon)
        else:
            self.me.latlon = None

        if changed:
            return f"OK - owner.{setting}={coord_value}"

        return f"OK - owner.{setting} unchanged"

    def _owner_set_command(self, name, value):
        setting = self._normalise_owner_setting(name)
        if setting is None:
            return None

        if setting == 'name':
            return self._owner_set_name(value)

        if setting == 'all':
            # Treat 'set owner ...' as setting owner name
            return self._owner_set_name(value)

        if setting == 'latlon':
            coords = value.replace(',', ' ').split()
            if len(coords) != 2:
                raise ValueError("Expected lat,lon")
            return self._owner_set_latlon(coords[0], coords[1])

        if setting in ('lat', 'lon'):
            return self._owner_set_single_coord(setting, value)

        return None

    def _radio_config_map(self):
        freq, bw, sf, cr, tx_power, tx_max = self.dispatch.get_radioconfig()

        freq_hz = int(self.config.get('radio.frequency_hz', int(freq) * 1000))
        bw_hz = int(self.config.get('radio.bandwidth_hz', int(bw)))
        sf = int(self.config.get('radio.sf', int(sf)))
        cr = int(self.config.get('radio.cr', int(cr)))
        tx_power = int(self.config.get('radio.txpower', int(tx_power)))
        rx_gain = bool(self.config.get('radio.rxgain', True))
        region = str(self.config.get('radio.region', 'custom'))

        return {
            'frequency': freq_hz // 1000,
            'bandwidth': bw_hz,
            'spreading_factor': sf,
            'coding_rate': cr,
            'tx_power': tx_power,
            'tx_power_max': tx_max,
            'rx_gain': rx_gain,
            'region': region,
        }

    def _radio_get_command(self, name):
        setting = self._normalise_radio_setting(name)
        if setting is None:
            return None

        radio = self._radio_config_map()
        freq_text = f"{radio['frequency'] / 1000.0:.3f}"
        bw_khz = radio['bandwidth'] / 1000.0
        bw_text = f"{bw_khz:g}"

        if setting == 'all':
            # Keep this parse-friendly for the companion app: freq_mhz,bw_khz,sf,cr
            return f"{freq_text},{bw_text},{radio['spreading_factor']},{radio['coding_rate']}"

        if setting == 'frequency':
            return freq_text

        if setting == 'bandwidth':
            return bw_text

        if setting == 'tx_power':
            return str(radio['tx_power'])

        if setting == 'rx_gain':
            return self._format_on_off(radio['rx_gain'])

        if setting == 'region':
            return radio['region']

        if setting == 'regions':
            return ','.join(self._supported_regions)

        return f"{setting}={radio[setting]}"

    def _radio_set_command(self, name, value):
        setting = self._normalise_radio_setting(name)
        if setting is None:
            return None

        if setting == 'all':
            values = [v.strip() for v in value.split(',')]
            if len(values) != 4:
                raise ValueError("Expected freq,bw,sf,cr")

            freq_hz = self._normalise_freq_hz(values[0])
            bw_hz = self._normalise_bw_hz(values[1])
            sf = int(values[2])
            cr = int(values[3])

            self.config.set('radio.frequency_hz', freq_hz, save=False)
            self.config.set('radio.bandwidth_hz', bw_hz, save=False)
            self.config.set('radio.sf', sf, save=False)
            self.config.set('radio.cr', cr, save=False)
            self.config.save()
            return self._radio_get_command('radio')

        if setting == 'frequency':
            freq_hz = self._normalise_freq_hz(value)
            self.config.set('radio.frequency_hz', freq_hz, save=True)
            return self._radio_get_command('frequency')

        if setting == 'bandwidth':
            bw_hz = self._normalise_bw_hz(value)
            self.config.set('radio.bandwidth_hz', bw_hz, save=True)
            return self._radio_get_command('bandwidth')

        if setting == 'spreading_factor':
            sf = int(value.strip())
            self.config.set('radio.sf', sf, save=True)
            return self._radio_get_command('spreading_factor')

        if setting == 'coding_rate':
            cr = int(value.strip())
            self.config.set('radio.cr', cr, save=True)
            return self._radio_get_command('coding_rate')

        if setting == 'tx_power':
            tx = int(value.strip())
            self.config.set('radio.txpower', tx, save=True)
            return self._radio_get_command('tx')

        if setting == 'rx_gain':
            rxgain = self._normalise_flag_value(value)
            self.config.set('radio.rxgain', rxgain, save=True)
            return self._radio_get_command('radio.rxgain')

        if setting == 'region':
            region = value.strip().upper()
            if region not in self._supported_regions and region != 'CUSTOM':
                raise ValueError("Unknown region")
            self.config.set('radio.region', region, save=True)
            return self._radio_get_command('region')

        return None

    def _get_admin_setting(self, name):
        spec = self._admin_setting_specs[name]
        for key in [name] + spec.get('fallback', []):
            value = self.config.get(key)
            if value is not None:
                return value

        if spec['type'] == list:
            return []

        return None

    def _format_admin_setting(self, value):
        if value is None:
            return "(unset)"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, list):
            return ",".join(value)

        return str(value)

    def _parse_admin_setting(self, name, raw_value):
        expected_type = self._admin_setting_specs[name]['type']
        value = raw_value.strip()

        if expected_type == int:
            return int(value)

        if expected_type == bool:
            lowered = value.lower()
            if lowered in ('1', 'true', 'yes', 'on', 'enabled'):
                return True
            if lowered in ('0', 'false', 'no', 'off', 'disabled'):
                return False
            raise ValueError("Expected true/false")

        if expected_type == list:
            if value.lower() in ('', 'none', 'null', '[]', '-'):
                return []

            if value.startswith('['):
                parsed = ast.literal_eval(value)
                if not isinstance(parsed, list):
                    raise ValueError("Expected list")
                return [str(v).strip() for v in parsed if str(v).strip()]

            return [v.strip() for v in value.split(',') if v.strip()]

        return value

    def _admin_get_command(self, name):
        setting = self._normalise_admin_setting(name)
        if setting is None:
            return None

        value = self._get_admin_setting(setting)
        return f"{setting}={self._format_admin_setting(value)}"

    def _admin_set_command(self, name, value):
        setting = self._normalise_admin_setting(name)
        if setting is None:
            return None

        parsed = self._parse_admin_setting(setting, value)
        changed = self.config.set(setting, parsed, save=True)

        if changed:
            return f"OK - {setting}={self._format_admin_setting(parsed)}"

        current = self._get_admin_setting(setting)
        if current == parsed:
            return f"OK - {setting} unchanged"

        return f"ERR - Unable to set {setting}"

    def _compat_get_command(self, name):
        key = name.strip().lower()

        if key == 'repeat':
            repeat_enabled = bool(self.config.get('repeat', self.repeater))
            return self._format_on_off(repeat_enabled)

        if key == 'advert.interval':
            value = int(self.config.get('advert.interval', 0))
            return str(value)

        if key == 'zerohop.advert.interval':
            value = int(self.config.get('zerohop.advert.interval', 0))
            return str(value)

        if key in ('owner.info', 'ownerinfo'):
            return str(self.config.get('owner.info', ''))

        if key == 'prv.key':
            return self._get_private_key()

        return None

    def _compat_set_command(self, name, value):
        key = name.strip().lower()
        raw = value.strip()

        if key == 'repeat':
            repeat_enabled = self._normalise_flag_value(raw)
            self.repeater = repeat_enabled
            self.config.set('repeat', repeat_enabled, save=True)
            return f"OK - repeat={self._format_on_off(repeat_enabled)}"

        if key == 'advert.interval':
            interval = int(raw)
            if interval < 0:
                raise ValueError("Expected non-negative interval")
            self.config.set('advert.interval', interval, save=True)
            return f"OK - advert.interval={interval}"

        if key == 'zerohop.advert.interval':
            interval = int(raw)
            if interval < 0:
                raise ValueError("Expected non-negative interval")
            self.config.set('zerohop.advert.interval', interval, save=True)
            return f"OK - zerohop.advert.interval={interval}"

        if key in ('owner.info', 'ownerinfo'):
            self.config.set('owner.info', value, save=True)
            return "OK - owner.info updated"

        if key == 'prv.key':
            return self._set_private_key(raw)

        return None

    def _password_command(self, value):
        new_password = value.strip()
        if not new_password:
            raise ValueError("Expected password text")
        self.config.set('admin.password', new_password, save=True)
        return "OK - admin.password updated"


    async def cli_command(self, command):
        """
        Process a CLI command

        Return a text response if the command was recognised, None if not
        """

        command_text = self._canonicalise_command_text(command.decode('utf8', errors='replace').strip())
        command_lc = command_text.lower()

        if command_lc == "advert":
            await self.tx_advert(flood=True)
            return "OK - Advert sent"
        if command_lc in ("advert.zerohop", "advert zerohop"):
            await self.tx_advert(flood=False)
            return "OK - Zero-hop advert sent"
        if command_lc == "clock":
            # The MeshCore firmware returns UTC time in the format "HH:MM - DD/MM/YYYY UTC"
            return time.strftime("%H:%M - %d/%m/%Y UTC", time.gmtime())
        if command_lc in ("clock sync", "clocksync"):
            return "OK - clock synced"
        if command_lc == "ver":
            return f"{self.version} ({self.version_date})"
        if command_lc == "board":
            return self._board_command()
        if command_lc in ("neighbors", "neighbours"):
            return self.neighbours()
        if command_lc in (
            "neighbors.zerohop",
            "neighbours.zerohop",
            "zerohop.neighbors",
            "zerohop.neighbours",
            "zerohop.neighbors",
            "zerohop.neighbours",
        ):
            return self.zero_hop_neighbours()
        if command_lc in ("discover.neighbors", "discover.neighbours", "discover neighbors", "discover neighbours"):
            await self.tx_advert(flood=False)
            await self.tx_advert(flood=True)
            return "OK - neighbor discovery triggered"
        if command_lc == "clear stats":
            return self._clear_stats_command()
        if command_lc in ("stats-core", "stats core"):
            return self._stats_core_command()
        if command_lc in ("stats-radio", "stats radio"):
            return self._stats_radio_command()
        if command_lc in ("stats-packets", "stats packets"):
            return self._stats_packets_command()
        if command_lc == "log":
            return self._log_command()
        if command_lc == "log start":
            return self._log_command('start')
        if command_lc == "log stop":
            return self._log_command('stop')
        if command_lc == "log erase":
            return self._log_command('erase')
        if command_lc.startswith("password "):
            try:
                return self._password_command(command_text.split(None, 1)[1])
            except ValueError as e:
                return f"ERR - {e}"
        if command_lc == "reboot":
            return "OK - reboot requested"
        if command_lc == "erase":
            return "ERR - erase not supported"

        # Supported forms:
        #   get <setting>
        #   set <setting> <value>
        #   <setting>               (same as get)
        #   <setting>=<value>       (same as set)
        command_parts = command_text.split(None, 2)
        command_head_parts = command_text.split(None, 1)

        if len(command_head_parts) >= 2 and command_head_parts[0].lower() in ('get', 'show'):
            query = command_head_parts[1]

            if query.lower() in (
                "neighbors.zerohop",
                "neighbours.zerohop",
                "zerohop.neighbors",
                "zerohop.neighbours",
                "zerohop.neighbors",
                "zerohop.neighbours",
            ):
                return self.zero_hop_neighbours()

            response = self._compat_get_command(query)
            if response is not None:
                return response

            response = self._owner_get_command(query)
            if response is not None:
                return response

            response = self._radio_get_command(query)
            if response is not None:
                return response

            response = self._admin_get_command(query)
            if response is not None:
                return response

        if len(command_parts) == 3 and command_parts[0].lower() == 'set':
            try:
                response = self._compat_set_command(command_parts[1], command_parts[2])
            except ValueError as e:
                return f"ERR - {e}"

            if response is not None:
                return response

            try:
                response = self._radio_set_command(command_parts[1], command_parts[2])
            except ValueError as e:
                return f"ERR - {e}"

            if response is not None:
                return response

            try:
                response = self._owner_set_command(command_parts[1], command_parts[2])
            except ValueError as e:
                return f"ERR - {e}"

            if response is not None:
                return response

            try:
                response = self._admin_set_command(command_parts[1], command_parts[2])
            except ValueError as e:
                return f"ERR - {e}"

            if response is not None:
                return response

        if '=' in command_text:
            name, value = command_text.split('=', 1)
            try:
                response = self._compat_set_command(name, value)
            except ValueError as e:
                return f"ERR - {e}"

            if response is not None:
                return response

            try:
                response = self._radio_set_command(name, value)
            except ValueError as e:
                return f"ERR - {e}"

            if response is not None:
                return response

            try:
                response = self._owner_set_command(name, value)
            except ValueError as e:
                return f"ERR - {e}"

            if response is not None:
                return response

            try:
                response = self._admin_set_command(name, value)
            except ValueError as e:
                return f"ERR - {e}"

            if response is not None:
                return response
        else:
            response = self._compat_get_command(command_text)
            if response is not None:
                return response

            response = self._owner_get_command(command_text)
            if response is not None:
                return response

            response = self._radio_get_command(command_text)
            if response is not None:
                return response

            response = self._admin_get_command(command_text)
            if response is not None:
                return response

        # Not recognised
        return None

    # Send a text message with all the details supplied;
    # returns the ackhash
    async def tx_text(self, recipient, txt_type, attempt, timestamp, text):
        textpacket = packet.MC_Text_Out(self.me, recipient, text, txt_type, attempt, timestamp)
        
        # Store the ackhash of the message
        msghash = textpacket.message_ackhash()

        logger.info(f"Sending text, attempt {attempt+1}, waiting for {msghash}")

        await self.transmit_packet(textpacket)

        return msghash

    async def rx_text_data(self, rx_packet:packet.MC_Text):
        """
        A text message has been received. If this is a repeater, treat it the same as CLI data
        """
        # Override this in a room server
        await self.rx_cli_data(rx_packet)

    async def rx_cli_data(self, rx_packet:packet.MC_Text):
        """
        CLI request
        """

        # Only accept CLI commands from logged in admin users
        if not rx_packet.source.admin:
            logger.info(f"Non-admin user {rx_packet.source.name} attempted CLI command")
            return

        command = rx_packet.text.strip()

        # Commands from a companion app's menu are prefixed with a number and |
        # eg. 01|advert
        if b'|' in command:
            (tag, command) = command.split(b'|', 1)
        else:
            tag = None

        logger.info(f"Command: {command.decode(errors='replace')} from {rx_packet.source.name}")

        response = await self.cli_command(command)

        if response is not None:
            if isinstance(response, str):
                response = response.encode('utf8')

            logger.info(f"Command {command.decode(errors='replace')} executed, reponse: {response.decode(errors='replace')}")
            self._record_log(f"{command.decode(errors='replace')} => {response.decode(errors='replace')}")
        else:
            logger.info(f"Unknown command: {command.decode(errors='replace')}")
            response = b"Unknown command"
            self._record_log(f"{command.decode(errors='replace')} => Unknown command")

        if tag:
            response = tag + b'|' +response

        # Timestamp on responses is the incoming timestamp plus 1, per the Meshcore source:
        # "// WORKAROUND: the two timestamps need to be different, in the CLI view"
        current_taskgroup.get().create_task(self.tx_text(rx_packet.source, packet.MC_Packet.TXT_TYPE_CLI_DATA, 0,
                                         rx_packet.timestamp+1, response))


    async def rx_text(self, rx_packet:packet.MC_Text):
        # Received text from client
        if rx_packet.txt_type == packet.MC_Packet.TXT_TYPE_PLAIN:
            await self.rx_text_data(rx_packet)
        elif rx_packet.txt_type == packet.MC_Packet.TXT_TYPE_CLI_DATA:
            await self.rx_cli_data(rx_packet)
        else:
            logger.warning(f"Unknown text type: {rx_packet.txt_type}")
    
    # When a client logs in. eg, room servers will start sending stored messages
    async def logged_in(self, pubkey):
        pass

    # Repeater device stats
    # Room server device stats are the same, but with a couple of extra stats which need tacking on
    # in the room server subclass
    def devicestats(self, rx_rssi, rx_snr):
        # Return a bytes object containing device stats
        # Battery (mV)  - 2 bytes
        # TX queue length - 2 bytes
        # noise floor - 2 bytes, signed
        # last RSSI - 2 bytes, signed
        # number packets received - 4 bytes
        #    "     "     sent - 4 bytes
        # air time (seconds) - 4 bytes
        # uptime (seconds) - 4 bytes
        # number...
        #   sent flood - 4 bytes
        #   sent direct - 4 bytes
        #   rec flood - 4 bytes
        #   rec direct - 4 bytes
        #   errors - 2 bytes
        # last SNR - 2 bytes, signed ( *4 )
        # number of direct message duplicates - 2 bytes
        # number of flood message duplicates - 2 bytes
        #
        # The RSSI and SNR are for the last received packet, which will be
        # the one that requested the stats
        data = struct.pack("<HHhhLLLLLLLLHhHH",
            self.hardware.batterymillivolts(),       # Battery
            self.dispatch.queue_length(), # TX queue
            self._noise_floor_dbm(),   # Noise floor (dBm)
            int(rx_rssi),   # Last packet RSSI
            self.stats["received"], # RX
            self.stats["sent"],          # TX
            int(self.dispatch.airtime),  # Airtime
            int(time.time() - self.begintime), # Uptime
            self.stats["sent.Flood"], self.stats["sent.Direct"],
            self.stats["received.Flood"], self.stats["received.Direct"],
            self.stats["badpacket"], # errors
            int(rx_snr * 4), # SNR
            self.stats["duplicate.Direct"], self.stats["duplicate.Flood"]
            )

        return data

    def telemetrydata(self, rx_rssi, rx_snr):
        # Telemetry currently reuses the device stats payload format so companion
        # apps can request telemetry from admin endpoints.
        return self.devicestats(rx_rssi, rx_snr)

    def login_success(self, pubkey, admin=False):
        # Successful login
        dest = AnonIdentity(pubkey)
        dest.create_shared_secret(self.me.private_key)
        dest.admin = admin
        return dest

    def login(self, pubkey, password):
        """
        Check login details

        Returns an AnonIdentity if successful, None if not; the AnonIdentity will have the
        admin flag set if the user is an admin
        """

        admin_pw = self.config.get('admin.password')
        admin_keys = self.config.get('admin.keys', self.config.get('admin.pubkeys', []))

        if admin_pw is not None and password == admin_pw.encode('utf8'):
            logger.info(f"Admin login for {hexlify(pubkey).decode('utf8')} by password")
            return self.login_success(pubkey, admin=True)

        if hexlify(pubkey).decode('utf8') in admin_keys:
            logger.info(f"Admin login for {hexlify(pubkey).decode('utf8')} by pubkey")
            return self.login_success(pubkey, admin=True)

        if self.config.get('guest.open', True):
            logger.info(f"Guest login for {hexlify(pubkey).decode('utf8')}")
            return self.login_success(pubkey, admin=False)

        guest_pw = self.config.get('guest.password')
        guest_keys = self.config.get('guest.keys', self.config.get('guest.pubkeys', []))

        if guest_pw is not None and password == guest_pw.encode('utf8'):
            logger.info(f"Guest login for {hexlify(pubkey).decode('utf8')} by password")
            return self.login_success(pubkey, admin=False)

        if hexlify(pubkey).decode('utf8') in guest_keys:
            logger.info(f"Guest login for {hexlify(pubkey).decode('utf8')} by pubkey")
            return self.login_success(pubkey, admin=False)

        # Login failed
        return None

    async def rx_anonreq(self, rx_packet):
        # This method is only called for decrypted requests
        logger.debug(f"Received ANON_REQ from {hexlify(rx_packet.senderpubkey).decode()}")

        # Check login

        dest = self.login(rx_packet.senderpubkey, rx_packet.password)
        if not dest:
            logger.info(f"Login failed for {hexlify(rx_packet.senderpubkey).decode()}")
            # No response to a failed login; the client will time out
            return

        self.ids.add_identity(dest)

        # The only response to an ANON_REQ appears to be 0 (RESP_SERVER_LOGIN_OK).
        # Any sort of failure (eg, wrong password) is just ignored and the client times out
        #
        #  * Response (RESP_SERVER_LOGIN_OK)
        #  * Reccomended keepalive interval (deprecated, now always 0)
        #  * is_admin?
        #  * Permissions (various PERM_ACL_ options, currently 0; PERM_ACL_GUEST)
        #  * random number (4 bytes)
        data = bytes([packet.MC_Packet.RESP_SERVER_LOGIN_OK, 0, 1 if dest.admin else 0, 0]) + randbytes(4)

        if rx_packet.is_flood():
            # Return a PATH packet with the response
            timestamp = struct.pack("<L", unique_time())

            response = packet.MC_Path_Out(self.me, dest, rx_packet.path, response=timestamp+data)
        else:
            # Packet came direct, no need to tell the sender how to get here
            response = packet.MC_Response_Out(self.me, dest, data)

        await self.transmit_packet(response)

        # Trigger anything that happens when a client logs in
        await self.logged_in(rx_packet)

    async def rx_req(self, rx_packet):
        logger.debug(f"Request: {rx_packet.request}")

        if rx_packet.request == packet.MC_Packet.REQ_TYPE_GET_STATUS:
            # Stats
            logger.debug(f"Status/stats request from {rx_packet.source.name}")

            data = self.devicestats(rx_packet.rssi, rx_packet.snr)

            # Response - timestamp from request (4 bytes), plus repeater stats data from above

            if rx_packet.is_flood():
                # Return a PATH packet with the response
                ts = struct.pack("<L", rx_packet.timestamp)

                response = packet.MC_Path_Out(self.me, rx_packet.source, rx_packet.path, response=ts+data)
            else:
                # Packet came direct, no need to tell the sender how to get here
                response = packet.MC_Response_Out(self.me, rx_packet.source, data, rx_packet.timestamp)

            await self.transmit_packet(response)
        elif rx_packet.request == packet.MC_Packet.REQ_TYPE_GET_TELEMETRY_DATA:
            logger.debug(f"Telemetry request from {rx_packet.source.name}")

            data = self.telemetrydata(rx_packet.rssi, rx_packet.snr)

            if rx_packet.is_flood():
                ts = struct.pack("<L", rx_packet.timestamp)
                response = packet.MC_Path_Out(self.me, rx_packet.source, rx_packet.path, response=ts+data)
            else:
                response = packet.MC_Response_Out(self.me, rx_packet.source, data, rx_packet.timestamp)

            await self.transmit_packet(response)
        else:
            logger.info(f"Unknown REQ type: {rx_packet.request}")

    def get_stats(self):
        # Return stats for this device
        stats = super().get_stats()

        stats['uptime'] = int(time.time() - self.begintime)
        stats['neighbours'] = len(self.neighbour_ids.get_all())

        return stats

    # Start flood and direct advert tasks
    async def start(self):
        await super().start()

        # Start the advert tasks
        current_taskgroup.get().create_task(self.tx_advert_flood(), name="Flood advert task")
        current_taskgroup.get().create_task(self.tx_advert_direct(), name="Direct advert task")

