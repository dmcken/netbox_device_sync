'''Driver for Tachyon Networks devices - a session-cookie authenticated
JSON REST API under /cgi.lua/*.

Confirmed live against two real units, sharing the same API family
(same Xavante-served /cgi.lua/* surface, different app.jsx builds):

- A TNS-100 (firmux 1.12.6, serial TNS1001252300369): a 6-port PoE
  distribution switch (5x 2.5GbE PoE + 1x 10GbE SFP+ uplink) deployed
  at a tower site, feeding sector radios and uplinking to the site
  router - not a wireless radio itself (capabilities()'s own `radios`
  block is empty on this unit).
- A TNA-303X (firmux 1.12.2, serial TNA3031422400137): a 60GHz PtMP
  sector radio (one `wlan0` radio, capabilities()'s `radios` block
  confirms band/vendor), bridging its one wireless VAP with a 2-port
  copper failover pair (eth0/eth1, sharing one internal switch chip -
  unlike the TNS-100's flat per-port capabilities, this one nests
  multiple physical sub-ports under a single logical port name, so its
  capabilities() speed isn't trustworthy for per-interface type
  detection - see _SFP_PORT_TYPE's use below).

/cgi.lua/config is only readable by an admin-level (level 0) account -
confirmed live that a read-only (level 9) account gets a 401 on it
(and on /cgi.lua/config_installer, the level-9 equivalent) even though
it can read /cgi.lua/status and /cgi.lua/capabilities freely. config()
is the only source of this device's configured VLANs (and, on a radio,
its live wireless PSK) - everything else this driver needs (interfaces,
IPs, port media type, wireless frequency/channel/role) is available at
either privilege level.
'''
# System imports
import ipaddress
import logging
import re

# External imports
import requests

# Local imports
import drivers.base

logger = logging.getLogger(__name__)

# capabilities()'s per-port `speed` (10000 vs 2500) is what actually
# distinguishes the TNS-100's one SFP+ cage from its copper PoE ports -
# confirmed live rather than assumed by port name, since a different
# unit could plausibly number its ports differently. Only trustworthy
# when that port's capabilities entry describes a single physical port
# directly (no nested `ports` sub-array - see get_interfaces()).
_SFP_PORT_TYPE = '10gbase-x-sfpp'
_COPPER_PORT_TYPE = '2.5gbase-t'

# Confirmed live on a TNA-303X: 32 pre-allocated per-peer-slot pseudo
# interfaces ("prs0".."prs31", matching its PtMP radio's maxPeerCount)
# always show up in status() regardless of how many peers are actually
# connected right now - all with a link-local-only IPv6 address and no
# real traffic. Not real interfaces (never appear in config() at all),
# so excluded here rather than left to be silently dropped downstream
# by the global link-local IP filter.
_PEER_SLOT_RE = re.compile(r'^prs\d+$')


class Tachyon(drivers.base.DriverBase):
    '''Tachyon Networks device driver (confirmed live: TNS-100, TNA-303X).

    Uses its own dedicated DEV_TACH_USERNAME/DEV_TACH_PASSWORD
    credential rather than the shared DEV_USERNAME/DEV_PASSWORD used by
    most other drivers - see .env.example.
    '''

    _connect_params = {
        'hostname':      {'dest': 'host'},
        'tach_username': {'dest': 'username'},
        'tach_password': {'dest': 'password'},
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
                params={'type': 'network,interfaces,ethernet,system,wireless'},
                timeout=30,
            )
            rez.raise_for_status()
            self._cache['status'] = rez.json()
        return self._cache['status']

    def get_interfaces(self) -> list[drivers.base.Interface]:
        config = self._fetch_config()
        config_ports = config.get('ethernet', {}).get('ports', {})
        config_radios = config.get('wireless', {}).get('radios', {})
        status_by_name = self._fetch_status().get('interfaces', {})
        capabilities_ports = self._fetch_capabilities().get('ports', {})

        interfaces = []

        # The bridge all physical ports (and, on a radio, its wireless
        # VAP too) belong to, and the interface this device's own
        # routable IP actually sits on - built first, matching the
        # bridges/parents-before-members ordering used elsewhere in
        # this project.
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
            port_caps = capabilities_ports.get(name, {})

            if 'ports' in port_caps:
                # Confirmed live on a TNA-303X: this name is actually a
                # 2-port switch chip (its own `ports` sub-array lists
                # each physical port's own speed), so the top-level
                # `speed` here doesn't reliably describe this single
                # logical interface - don't guess a specific type from
                # it, unlike the TNS-100's flat per-port capabilities.
                port_type = None
            else:
                port_type = _SFP_PORT_TYPE if port_caps.get('speed') == 10000 else _COPPER_PORT_TYPE

            interfaces.append(drivers.base.Interface(
                name=name,
                bridge='br-wan',
                description=port_config.get('note') or None,
                mac_address=[port_mac] if port_mac else [],
                mtu=port_config.get('mtu'),
                type=port_type,
            ))

        for name in config_radios:
            radio_status = status_by_name.get(name, {})
            radio_mac = radio_status.get('mac_address')

            interfaces.append(drivers.base.Interface(
                name=name,
                bridge='br-wan',
                mac_address=[radio_mac] if radio_mac else [],
                mtu=radio_status.get('mtu'),
                # Left unset (rather than guessed at a specific 802.11
                # standard - this is 60GHz 802.11ad on the TNA-303X, but
                # NetBox has no matching wireless PHY choice for that)
                # - sync_wireless()'s _ensure_wireless_type() bumps this
                # to 'other-wireless' itself once it processes this
                # radio's WirelessRadio data, same as every other driver.
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
            if name == 'lo' or _PEER_SLOT_RE.match(name):
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

    def get_wireless_radios(self) -> list[drivers.base.WirelessRadio]:
        '''This device's own wireless radio(s) - none on a TNS-100
        (config().wireless is absent entirely), one (`wlan0`, 60GHz,
        PtMP AP) confirmed live on a TNA-303X.

        Radio-level frequency/channel width comes from status() (the
        device's live report); SSID/security/PSK come from config()'s
        per-VAP entry (status() only has a human-readable `security`
        summary string, not the actual PSK). A radio can carry more
        than one VAP (multiple SSIDs) - config's and status's VAP lists
        are correlated by position within the same radio's list, since
        neither side gives them an explicit shared id and this hasn't
        been confirmed live against a unit with more than one VAP.

        Peer parsing confirmed live against a second TNA-303X with 4
        real connected CPEs: a peer's human-readable label (e.g. a
        customer name) is status.wireless.peers[].system_name, NOT
        "hostname" as originally guessed when this was written against
        a unit with zero connected peers - fixed once real data was
        available. peers[].model (e.g. "TNA-303L-65") is the peer's own
        reported hardware model, used elsewhere to fuzzy-match a NetBox
        device type when auto-provisioning a placeholder for a peer
        with no existing NetBox interface. ipv4/ipv6 are the peer's own
        bare addresses (no prefix reported), recorded as host routes
        (/32, /128) rather than guessing at a subnet.
        '''
        config_radios = self._fetch_config().get('wireless', {}).get('radios', {})
        if not config_radios:
            return []

        status_wireless = self._fetch_status().get('wireless', {})
        status_radios = status_wireless.get('radios', {})
        live_peers = status_wireless.get('peers', [])

        status_vaps_by_radio: dict[str, list[dict]] = {}
        for vap in status_wireless.get('vaps', []):
            status_vaps_by_radio.setdefault(vap.get('radio'), []).append(vap)

        peers = []
        for peer in live_peers:
            mac = peer.get('mac')
            if not mac:
                continue

            peer_ips = []
            for key, prefixlen in (('ipv4', 32), ('ipv6', 128)):
                raw = peer.get(key)
                if not raw:
                    continue
                try:
                    peer_ips.append(ipaddress.ip_interface(f"{raw}/{prefixlen}"))
                except ValueError:
                    logger.error(f"Unable to parse peer {key} on '{mac}': {raw}")

            peers.append(drivers.base.WirelessPeer(
                mac=mac,
                hostname=peer.get('system_name'),
                model=peer.get('model'),
                ip_addresses=peer_ips or None,
            ))

        radios = []
        for radio_name, radio_config in config_radios.items():
            radio_status = status_radios.get(radio_name, {})
            status_vaps = status_vaps_by_radio.get(radio_name, [])

            for idx, vap_config in enumerate(radio_config.get('vaps', [])):
                vap_status = status_vaps[idx] if idx < len(status_vaps) else {}
                passphrase = vap_config.get('security', {}).get('wpapsk', {}).get('passphrase')

                radios.append(drivers.base.WirelessRadio(
                    interface=radio_name,
                    # 'master' is this device's own confirmed-live AP
                    # role string (operationMode) - anything else is
                    # left unset rather than guessed at 'station'.
                    role='ap' if vap_status.get('operationMode') == 'master' else None,
                    ssid=vap_config.get('ssid'),
                    frequency_mhz=radio_status.get('frequency'),
                    channel_width_mhz=radio_status.get('channelWidth'),
                    security=vap_status.get('security'),
                    psk=passphrase,
                    peers=peers,
                ))

        return radios
