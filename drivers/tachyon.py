'''Driver for Tachyon Networks devices - a session-cookie authenticated
JSON REST API under /cgi.lua/*.

Confirmed live against a real TNS-100 (firmux 1.12.6, serial
TNS1001252300369): a 6-port PoE distribution switch (5x 2.5GbE PoE +
1x 10GbE SFP+ uplink) deployed at a tower site, feeding sector radios
and uplinking to the site router - not a wireless radio itself
(capabilities()'s own `radios` block is empty on this unit). Other
Tachyon product lines (wireless radios) aren't covered here yet.

/cgi.lua/config is only readable by an admin-level (level 0) account -
confirmed live that a read-only (level 9) account gets a 401 on it
(and on /cgi.lua/config_installer, the level-9 equivalent) even though
it can read /cgi.lua/status and /cgi.lua/capabilities freely. config()
is the only source of this device's configured VLANs, so an admin
account is needed for get_vlans() to return anything - everything else
this driver needs (interfaces, IPs, port media type) is available at
either privilege level.
'''
# System imports
import ipaddress
import logging

# External imports
import requests

# Local imports
import drivers.base

logger = logging.getLogger(__name__)

# capabilities()'s per-port `speed` (10000 vs 2500) is what actually
# distinguishes the one SFP+ cage from the copper PoE ports - confirmed
# live rather than assumed by port name, since a different TNS-100 unit
# could plausibly number its ports differently.
_SFP_PORT_TYPE = '10gbase-x-sfpp'
_COPPER_PORT_TYPE = '2.5gbase-t'


class Tachyon(drivers.base.DriverBase):
    '''Tachyon Networks device driver (confirmed live: TNS-100).'''

    _connect_params = {
        'hostname': {'dest': 'host'},
        'username': {'dest': 'username'},
        'password': {'dest': 'password'},
    }

    def _connect(self, host: str, username: str, password: str) -> None:
        self._host = host
        self._session = requests.Session()

        try:
            rez = self._session.post(
                self._url('cgi.lua/login'),
                json={'username': username, 'password': password},
                timeout=30,
            )
            auth_result = rez.json()
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.JSONDecodeError) as exc:
            raise drivers.base.ConnectError from exc

        if not auth_result.get('auth'):
            raise drivers.base.AuthenticationError(
                f"Login to Tachyon device '{host}' failed"
            )

    def _close(self) -> None:
        try:
            self._session.close()
            del self._session
        except AttributeError:
            pass

    def _url(self, path: str) -> str:
        return f"http://{self._host}/{path}"

    def _fetch_capabilities(self) -> dict:
        '''Fetch /cgi.lua/capabilities, with caching. Confirmed live to
        be readable at any privilege level, unlike config().'''
        if 'capabilities' not in self._cache:
            rez = self._session.get(self._url('cgi.lua/capabilities'), timeout=30)
            rez.raise_for_status()
            self._cache['capabilities'] = rez.json()
        return self._cache['capabilities']

    def _fetch_config(self) -> dict:
        '''Fetch /cgi.lua/config, with caching.

        Needs an admin-level account (see module docstring). Contains
        this device's local user password hashes and its SNMP
        community string/cloud API key - never log this dict wholesale,
        only the specific fields pulled out of it below.
        '''
        if 'config' not in self._cache:
            rez = self._session.get(self._url('cgi.lua/config'), timeout=30)
            rez.raise_for_status()
            self._cache['config'] = rez.json()
        return self._cache['config']

    def _fetch_status(self) -> dict:
        '''Fetch /cgi.lua/status, with caching. Needs a `type` query
        param or the device 400s ("'type' parameter missing") -
        confirmed live that this one call covers everything this
        driver needs.'''
        if 'status' not in self._cache:
            rez = self._session.get(
                self._url('cgi.lua/status'),
                params={'type': 'network,interfaces,ethernet,system'},
                timeout=30,
            )
            rez.raise_for_status()
            self._cache['status'] = rez.json()
        return self._cache['status']

    def get_interfaces(self) -> list[drivers.base.Interface]:
        config_ports = self._fetch_config().get('ethernet', {}).get('ports', {})
        status_by_name = self._fetch_status().get('interfaces', {})
        capabilities_ports = self._fetch_capabilities().get('ports', {})

        interfaces = []

        # The bridge all physical ports belong to, and the interface
        # this device's own routable IP actually sits on - built first,
        # matching the bridges/parents-before-members ordering used
        # elsewhere in this project.
        bridge_status = status_by_name.get('br-wan', {})
        bridge_mac = bridge_status.get('mac_address')
        interfaces.append(drivers.base.Interface(
            name='br-wan',
            mac_address=[bridge_mac] if bridge_mac else [],
            mtu=bridge_status.get('mtu'),
            type='bridge',
        ))

        for name, port_config in config_ports.items():
            port_status = status_by_name.get(name, {})
            port_mac = port_status.get('mac_address')
            port_speed = capabilities_ports.get(name, {}).get('speed')

            interfaces.append(drivers.base.Interface(
                name=name,
                bridge='br-wan',
                description=port_config.get('note') or None,
                mac_address=[port_mac] if port_mac else [],
                mtu=port_config.get('mtu'),
                type=_SFP_PORT_TYPE if port_speed == 10000 else _COPPER_PORT_TYPE,
            ))

        return interfaces

    def get_ipaddresses(self) -> list[drivers.base.IPAddress]:
        status = self._fetch_status()
        zone = self._fetch_config().get('network', {}).get('zones', {}).get('wan', {})

        # Confirmed live: mode == 'static' means the v4 address is a
        # manually-set one; anything else is treated as DHCP-assigned,
        # the same static/dhcp split used elsewhere in this project
        # (e.g. drivers/uisp.py's get_ipaddresses()).
        v4_status = 'active' if zone.get('mode') == 'static' else 'dhcp'
        # Confirmed live: even with ipv6.enabled == False (no manually-
        # configured v6 address), the interface still carries a real
        # global v6 address - autoconfigured (SLAAC), not unset.
        v6_status = 'active' if zone.get('ipv6', {}).get('enabled') else 'slaac'

        addresses = []
        for name, iface_status in status.get('interfaces', {}).items():
            if name == 'lo':
                continue

            raw_addresses = [
                *iface_status.get('ip_address', []),
                *iface_status.get('ip6_address', []),
            ]
            for raw in raw_addresses:
                try:
                    address = ipaddress.ip_interface(raw)
                except ValueError:
                    logger.error(f"Unable to parse address on '{name}': {raw}")
                    continue

                addresses.append(drivers.base.IPAddress(
                    address=address,
                    interface=name,
                    status=v6_status if address.version == 6 else v4_status,
                    vrf=None,
                ))

        return addresses

    def get_vlans(self) -> list[drivers.base.Vlan]:
        zone = self._fetch_config().get('network', {}).get('zones', {}).get('wan', {})

        return [
            drivers.base.Vlan(
                id=vlan['id'], name=vlan.get('name'), bridge='br-wan', status='active',
            )
            for vlan in zone.get('vlans', [])
        ]
