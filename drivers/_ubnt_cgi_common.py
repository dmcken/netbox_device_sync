'''Shared driver logic for Ubiquiti's .cgi-family devices (AirOSv8,
AirFiber) - both share byte-identical getcfg()/getstatus() schemas
(see ubnt_automata's airosv8.py/airfiber5x.py docstrings: AirFiber's
own docstring notes it "Shares the same auth/session mechanism as
AirOSv8"), so the netconf/bridge/status-interfaces parsing needed to
build Interface/IPAddress records only needs to be written once here,
mirroring ubnt_automata's own AirOSCommonDevice shared-base pattern.

Concrete drivers (drivers/airos.py, drivers/airfiber.py) just set
_device_class to the ubnt_automata class to wrap.
'''
# System imports
import ipaddress
import logging
import re

# External imports
import ubnt_automata
import ubnt_automata.exceptions

# Local imports
import drivers._ubnt_iface_utils
import drivers.base

logger = logging.getLogger(__name__)

# Matches AirFiber's uBond interfaces (e.g. 'ubond0') - see get_interfaces().
_UBOND_RE = re.compile(r'^ubond\d*$', re.IGNORECASE)


class UbntCgiDriverBase(drivers.base.DriverBase):
    '''Shared base for the .cgi-family Ubiquiti devices.'''

    _connect_params = {
        'hostname':     {'dest': 'host'},
        'username':     {'dest': 'username'},
        'password':     {'dest': 'password'},
        # Some Ubiquiti devices only support a single admin account, so a
        # dedicated automation account can't be created on them. When set,
        # these are tried before falling back to username/password (same
        # pattern as drivers/edgeos.py).
        'ubnt_username': {'dest': 'ubnt_username'},
        'ubnt_password': {'dest': 'ubnt_password'},
    }

    # Set by subclasses to the ubnt_automata class to wrap (AirOSv8 or
    # AirFiber) - both expose the same login_http()/getcfg()/getstatus()
    # surface used below.
    _device_class = None

    def _connect(self, **kwargs) -> None:
        credential_candidates = []
        if kwargs.get('ubnt_username') and kwargs.get('ubnt_password'):
            credential_candidates.append((kwargs['ubnt_username'], kwargs['ubnt_password']))
        credential_candidates.append((kwargs['username'], kwargs['password']))

        self._dev = self._device_class(kwargs['host'])

        last_exc = None
        for curr_username, curr_password in credential_candidates:
            try:
                logger.debug(
                    f"Attempting to connect to {kwargs['host']} as '{curr_username}'"
                )
                self._dev.login_http(curr_password, curr_username)
                return
            except ubnt_automata.exceptions.WrongPassword as exc:
                logger.debug(f"Login as '{curr_username}' failed, trying next credential")
                last_exc = exc
                continue
            except ubnt_automata.exceptions.DeviceUnavailable as exc:
                raise drivers.base.ConnectError from exc

        raise drivers.base.AuthenticationError from last_exc

    def _close(self) -> None:
        try:
            self._dev._req_session.close()
            del self._dev
        except AttributeError:
            pass

    def _fetch_cfg(self) -> dict[str, str]:
        '''Fetch getcfg.cgi's flat key=value config, with caching.'''
        if 'cfg' not in self._cache:
            self._cache['cfg'] = self._dev.getcfg()
        return self._cache['cfg']

    def _fetch_status(self) -> dict:
        '''Fetch status.cgi's structured JSON, with caching.'''
        if 'status' not in self._cache:
            self._cache['status'] = self._dev.getstatus()
        return self._cache['status']

    @staticmethod
    def _group_netconf(cfg: dict[str, str]) -> dict[str, dict[str, str]]:
        '''Group flat 'netconf.N.*' keys into {devname: {suffix: value}}.

        e.g. {'netconf.3.devname': 'br0', 'netconf.3.ip': '10.0.0.1', ...}
        -> {'br0': {'devname': 'br0', 'ip': '10.0.0.1', ...}, ...}
        '''
        by_index: dict[str, dict[str, str]] = {}
        for key, val in cfg.items():
            parts = key.split('.')
            if len(parts) < 3 or parts[0] != 'netconf' or not parts[1].isdigit():
                continue
            suffix = '.'.join(parts[2:])
            by_index.setdefault(parts[1], {})[suffix] = val

        return {
            entry['devname']: entry
            for entry in by_index.values()
            if 'devname' in entry
        }

    @staticmethod
    def _map_bridge_ports(cfg: dict[str, str]) -> dict[str, str]:
        '''Map {member interface devname: bridge devname} from the flat
        'bridge.N.devname'/'bridge.N.port.M.devname' keys.'''
        bridges: dict[str, dict] = {}
        for key, val in cfg.items():
            parts = key.split('.')
            if len(parts) < 3 or parts[0] != 'bridge' or not parts[1].isdigit():
                continue
            idx = parts[1]
            entry = bridges.setdefault(idx, {'ports': []})
            if parts[2] == 'devname':
                entry['devname'] = val
            elif parts[2] == 'port' and len(parts) >= 5 and parts[4] == 'devname':
                entry['ports'].append(val)

        port_to_bridge = {}
        for entry in bridges.values():
            bridge_name = entry.get('devname')
            if not bridge_name:
                continue
            for port in entry['ports']:
                port_to_bridge[port] = bridge_name

        return port_to_bridge

    def get_interfaces(self) -> list[drivers.base.Interface]:
        '''Build Interface records from status.cgi's `interfaces` array
        (the authoritative live interface list, with MAC/MTU/enabled),
        enriched with getcfg.cgi's bridge membership.'''
        status = self._fetch_status()
        port_to_bridge = self._map_bridge_ports(self._fetch_cfg())

        interfaces = []
        interfaces_with_plugged = []
        for curr_int in status.get('interfaces', []):
            name = curr_int['ifname']
            mac = curr_int.get('hwaddr')

            interface_record = drivers.base.Interface(
                name=name,
                mtu=curr_int.get('mtu'),
                mac_address=[mac] if mac else [],
            )

            if name in port_to_bridge:
                interface_record.bridge = port_to_bridge[name]

            if name in port_to_bridge.values():
                # This interface is itself a bridge.
                interface_record.type = 'bridge'
            elif _UBOND_RE.match(name):
                # AirFiber's uBond (adaptive multi-chain radio bonding) -
                # confirmed live on an AirFiber 60: ubond0 reports the
                # exact same MAC as the wlan0 radio chain it wraps, which
                # NetBox's managed-MAC model rejects assigning to two
                # interfaces at once. Flagging it 'lag' (like EdgeOS's own
                # driver does for its bond* interfaces) makes
                # set_interface_macs() skip it, same as bridge/virtual.
                interface_record.type = 'lag'

            interfaces.append(interface_record)
            interfaces_with_plugged.append(
                (interface_record, curr_int.get('status', {}).get('plugged'))
            )

        drivers._ubnt_iface_utils.dedupe_macs_by_plugged(interfaces_with_plugged)

        # Bridges/parents first, matching the ordering contract documented
        # on drivers.base.DriverBase.get_interfaces().
        interfaces.sort(key=lambda i: 0 if i.type == 'bridge' else 1)

        return interfaces

    def get_ipaddresses(self) -> list[drivers.base.IPAddress]:
        '''Build IPAddress records from getcfg.cgi's netconf.N.ip/netmask
        entries - the configured (static) addresses on each interface.'''
        netconf = self._group_netconf(self._fetch_cfg())

        addresses = []
        for devname, entry in netconf.items():
            ip = entry.get('ip')
            netmask = entry.get('netmask')
            if not ip or not netmask or ip == '0.0.0.0':
                continue

            try:
                address = ipaddress.ip_interface(f"{ip}/{netmask}")
            except ValueError:
                logger.error(f"Unable to parse address on '{devname}': {ip}/{netmask}")
                continue

            addresses.append(drivers.base.IPAddress(
                address=address,
                interface=devname,
                status='active',
                vrf=None,
            ))

        return addresses

    def get_gps(self) -> drivers.base.GPSCoordinate | None:
        '''This device's own GPS location, for devices with built-in
        GPS hardware (e.g. Rocket Prism, AirFiber) - confirmed live on
        an AirOSv8 Rocket Prism 5AC Gen2 and an AirFiber 5X HD.'''
        gps = self._dev.get_gps()
        if gps is None:
            return None

        return drivers.base.GPSCoordinate(
            latitude=gps.latitude,
            longitude=gps.longitude,
            altitude_m=gps.altitude_m,
        )

    def get_wireless_radios(self) -> list[drivers.base.WirelessRadio]:
        '''This device's own radio, plus whichever peer(s) are currently
        linked to it (one for a PtP link, several for a PtMP AP).

        wireless.apmac does NOT match any interface's own hwaddr
        (confirmed live on an airFiber 5X HD - some kind of virtual
        BSSID, not the radio's real MAC), so the radio interface can't
        be identified by MAC matching. Uses the interface name instead:
        'ath0' if present, else 'wlan0' - confirmed live to be the
        radio-facing interface across every AirOS/AirFiber unit tested,
        unlike the wired/bridge names (eth0/ueth0/ueth1/br0/br2), which
        vary by model. Returns nothing if this device has neither name,
        rather than guessing which interface is the radio.
        '''
        status = self._fetch_status()
        interface_names = {i['ifname'] for i in status.get('interfaces', [])}
        radio_name = 'ath0' if 'ath0' in interface_names else (
            'wlan0' if 'wlan0' in interface_names else None
        )
        if radio_name is None:
            return []

        wireless = status.get('wireless', {})
        mode = wireless.get('mode', '')
        role = 'ap' if mode.startswith('ap-') else (
            'station' if mode.startswith('sta-') else None
        )

        peers = []
        for sta in wireless.get('sta', []):
            mac = sta.get('mac')
            if not mac:
                continue
            peers.append(drivers.base.WirelessPeer(
                mac=mac,
                hostname=sta.get('remote', {}).get('hostname'),
            ))

        return [drivers.base.WirelessRadio(
            interface=radio_name,
            role=role,
            ssid=wireless.get('essid'),
            frequency_mhz=wireless.get('frequency'),
            channel_width_mhz=wireless.get('chanbw'),
            security=wireless.get('security'),
            psk=self._find_psk(self._fetch_cfg()),
            peers=peers,
        )]

    @staticmethod
    def _find_psk(cfg: dict[str, str]) -> str | None:
        '''Find the wireless PSK in getcfg()'s flat config.

        The exact key varies by model/firmware - confirmed live as
        'wireless.1.security.psk' on an AirFiber 5X HD, and (two
        identical copies of) 'aaa.1.wpa.psk'/'wpasupplicant.profile.1.
        network.1.psk' on an AirOSv8 Rocket Prism 5AC Gen2 - so this
        just takes the first key ending in '.psk' rather than assuming
        one exact path.
        '''
        for key, val in cfg.items():
            if key.endswith('.psk'):
                return val
        return None
