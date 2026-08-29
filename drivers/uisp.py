'''Driver for UISP-firmware Ubiquiti devices (Wave AP/Pro/Nano/LR,
AirFiber 60 XR, EdgePower, some EdgePoint switches) - see
ubnt_automata.UispDevice.
'''
# System imports
import ipaddress
import logging

# External imports
import ubnt_automata
import ubnt_automata.exceptions

# Local imports
import drivers._ubnt_iface_utils
import drivers.base

# UISP's own identification.type values that map cleanly onto NetBox's
# interface type vocabulary - anything else (e.g. "wireless") is left
# unset (defaults to NetBox's 'other'), matching this project's existing
# convention of not guessing at a specific 802.11 standard.
_TYPE_MAP = {
    'bridge': 'bridge',
}

logger = logging.getLogger(__name__)


class Uisp(drivers.base.DriverBase):
    '''UISP-firmware device driver.'''

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

    def _connect(self, **kwargs) -> None:
        credential_candidates = []
        if kwargs.get('ubnt_username') and kwargs.get('ubnt_password'):
            credential_candidates.append((kwargs['ubnt_username'], kwargs['ubnt_password']))
        credential_candidates.append((kwargs['username'], kwargs['password']))

        self._dev = ubnt_automata.UispDevice(kwargs['host'])

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

    def _fetch_interfaces(self) -> list[dict]:
        '''Fetch the interfaces route, with caching.'''
        if 'interfaces' not in self._cache:
            self._cache['interfaces'] = self._dev.get_interfaces()
        return self._cache['interfaces']

    def get_interfaces(self) -> list[drivers.base.Interface]:
        interfaces = []
        interfaces_with_plugged = []
        for raw in self._fetch_interfaces():
            identification = raw['identification']
            status = raw.get('status', {})

            mac = identification.get('mac')
            interface_record = drivers.base.Interface(
                name=identification['id'],
                description=status.get('description') or '',
                mtu=status.get('mtu'),
                mac_address=[mac] if mac else [],
                type=_TYPE_MAP.get(identification.get('type')),
            )
            interfaces.append(interface_record)
            interfaces_with_plugged.append((interface_record, status.get('plugged')))

        drivers._ubnt_iface_utils.dedupe_macs_by_plugged(interfaces_with_plugged)

        # Bridges/parents first, matching the ordering contract documented
        # on drivers.base.DriverBase.get_interfaces().
        interfaces.sort(key=lambda i: 0 if i.type == 'bridge' else 1)

        return interfaces

    def get_ipaddresses(self) -> list[drivers.base.IPAddress]:
        # Confirmed live on an EdgePower 24V-72W: eth0/eth1 share a single
        # IP stack and both report the exact same addresses regardless of
        # which port is actually connected - only `status.plugged`
        # distinguishes them. Without deduping this, sync_ips() flip-flops
        # the same NetBox IP record between the two interfaces every run
        # (each pass reassigns it to whichever of the pair was processed
        # last), producing an "Updating..." log line every single sync
        # with nothing actually changing. Grouping by address and
        # preferring the plugged interface avoids that; genuinely
        # ambiguous cases (none or more than one plugged) fall back to
        # reporting all of them rather than silently dropping data.
        by_cidr: dict[str, list[dict]] = {}
        for raw in self._fetch_interfaces():
            name = raw['identification']['id']
            plugged = raw.get('status', {}).get('plugged')

            for curr_address in raw.get('addresses', []):
                cidr = curr_address.get('cidr')
                if not cidr:
                    continue
                by_cidr.setdefault(cidr, []).append({
                    'interface': name,
                    'plugged': plugged,
                    'type': curr_address.get('type'),
                })

        addresses = []
        for cidr, candidates in by_cidr.items():
            plugged_candidates = [c for c in candidates if c['plugged'] is True]
            to_emit = plugged_candidates if len(plugged_candidates) == 1 else candidates

            try:
                address = ipaddress.ip_interface(cidr)
            except ValueError:
                logger.error(f"Unable to parse address: {cidr}")
                continue

            for candidate in to_emit:
                # Dynamic (SLAAC/DHCP) vs static - NetBox's own vocabulary
                # distinguishes v6 autoconfiguration ('slaac') from v4
                # ('dhcp'); not confirmed against a real DHCP-assigned v4
                # capture, this generation was only seen with static v4 +
                # link-local v6 in practice.
                if candidate['type'] == 'static':
                    status = 'active'
                elif address.version == 6:
                    status = 'slaac'
                else:
                    status = 'dhcp'

                addresses.append(drivers.base.IPAddress(
                    address=address,
                    interface=candidate['interface'],
                    status=status,
                    vrf=None,
                ))

        return addresses

    def get_neighbours(self) -> list[drivers.base.Neighbour]:
        '''MAC/IP pairs seen per physical port (tools/mac-table) - the
        closest equivalent to an ARP table this API exposes.'''
        neighbours = []
        for entry in self._dev.get_mac_table():
            mac = entry.get('mac')
            raw_address = entry.get('address')
            if not mac or not raw_address:
                continue

            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError:
                logger.error(f"Unable to parse mac-table address: {raw_address}")
                continue

            port = entry.get('port', {})
            neighbours.append(drivers.base.Neighbour(
                mac=[mac],
                ip=address,
                interface=port.get('name') or port.get('id'),
                source='mac-table',
            ))

        return neighbours
