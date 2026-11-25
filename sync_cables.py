#!/usr/bin/python3
'''Build real Netbox Cable objects from live LLDP neighbour data.

Connects to every Netbox device whose platform has LLDP support (Junos,
RouterOS), collects each one's LLDP neighbour table, and only creates a
cable once both ends of it are pinned down to a real port:

- Who the neighbour is. LLDP reports the neighbour's own hostname, which
  often differs from its Netbox name (a Junos routing engine reports
  "DC1-IE2-RE1" for "DC1-IE2", a switch says "SW1" where Netbox says
  "SW01"). The name is matched exactly first, then with those
  differences ignored, then as a shortened/lengthened form of exactly
  one Netbox name ("TTIXv2" for "DC-DC1-TTIXv2"). A member of a virtual
  chassis stands for the chassis master, which holds the ports in
  Netbox. Every match that was not exact is listed so the Netbox name or
  the device's hostname can be corrected; a neighbour that matches
  nothing is listed as a device missing from Netbox, along with the
  device Netbox has its MAC address recorded on, if any.
- Which port on this device. Each side's own reported local port is
  authoritative, but only a physical port can take a cable: a neighbour
  heard over a bridge, VLAN, bond or tunnel is dropped.
- Which port on the neighbour. The port the neighbour advertised is used
  when it names a real interface of that device in Netbox (a MikroTik,
  NX-OS or Arista neighbour advertises its port name; most Juniper
  switches only a free-text description, which then matches nothing and
  is ignored). Otherwise the neighbour's own report of the same link
  supplies it.

A link is created when
- both devices report each other and the ports pair up, through the
  advertised port names or because it is the only link between the two;
- or one device reports it and the advertised port names a real, free
  interface of the neighbour, which itself reported nothing that
  contradicts it (typically a device we cannot log in to).

Anything else - parallel links whose ports cannot be told apart, a
neighbour missing from Netbox - is listed for manual review, never
guessed at. An interface that already has a cable is left alone; if that
cable goes somewhere other than where LLDP says, it is listed as a
conflict so the Netbox record can be checked.

Defaults to a dry-run report of what it would do; pass --commit to
actually create the cables.
'''

# System imports
import argparse
import collections
import logging
import os
import re

# External imports
import dotenv
import pynetbox

# Local imports
import drivers.base
import drivers.junos
import drivers.routeros
import utils

dotenv.load_dotenv()

LOGGING_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logger = logging.getLogger(__name__)

# Only platforms with a get_neighbours() LLDP implementation.
PLATFORM_TO_DRIVER = {
    'JunOS':    drivers.junos.JunOS,
    'RouterOS': drivers.routeros.RouterOS,
}


def parse_arguments() -> argparse.Namespace:
    '''Parse CLI arguments.'''
    parser = argparse.ArgumentParser(
        prog="LLDP cable sync",
        description=__doc__,
    )
    parser.add_argument(
        '-n', '--netbox-device', nargs='+', default=[],
        help=(
            "Only pull LLDP from these Netbox devices. A link to a device "
            "outside this scope will show as unconfirmed (that side's data "
            "wasn't collected), not wrongly created."
        ),
    )
    parser.add_argument(
        '--commit', action='store_true',
        help="USE WITH CAUTION. Actually create the confirmed cables in "
             "Netbox. Without this, only a report is printed.",
    )
    parser.add_argument(
        '-d', '--debug', action='store_true', help="Verbose logging.",
    )
    return parser.parse_args()


# Interface types that can never be the end of a cable.
NON_PHYSICAL_INTERFACE_TYPES = {'virtual', 'bridge', 'lag'}

# Devices in these states are not candidates for a neighbour's identity -
# a retired device often shares its name's stem with its replacement.
RETIRED_DEVICE_STATUS = {'decommissioning', 'inventory'}

# "-RE0"/"-re1": the routing engine a Junos chassis answers LLDP as.
_ROUTING_ENGINE_RE = re.compile(r'[-_]re\d+$', re.IGNORECASE)


def _name_key(name: str) -> str:
    """Reduce a hostname to what should be identical between LLDP and
    Netbox: case, punctuation, a Junos routing-engine suffix and leading
    zeros in numbers ("SW01" vs "SW1") are all dropped."""
    name = _ROUTING_ENGINE_RE.sub('', name.strip().lower())
    name = re.sub(r'\d+', lambda m: str(int(m.group())), name)
    return re.sub(r'[^a-z0-9]', '', name)


def _name_tokens(name: str) -> tuple:
    """The same reduction, kept as the dash/underscore separated parts."""
    name = _ROUTING_ENGINE_RE.sub('', name.strip().lower())
    name = re.sub(r'\d+', lambda m: str(int(m.group())), name)
    return tuple(t for t in re.split(r'[^a-z0-9]+', name) if t)


class Inventory:
    """Netbox devices, interfaces and MAC addresses, as needed to turn an
    LLDP neighbour entry into a (device, interface) pair."""

    def __init__(self, nb_api):
        self._nb_api = nb_api
        self.devices = [
            d for d in nb_api.dcim.devices.all()
            if d.name and d.status.value not in RETIRED_DEVICE_STATUS
        ]
        self._by_name = {d.name.strip().lower(): d for d in self.devices}
        self._by_key = collections.defaultdict(list)
        for device in self.devices:
            self._by_key[_name_key(device.name)].append(device)
        self._by_id = {d.id: d for d in self.devices}
        self._mac_to_device = None
        self._interfaces = {}

    def _device_by_mac(self, macs):
        if self._mac_to_device is None:
            owners = collections.defaultdict(set)
            for mac in self._nb_api.dcim.mac_addresses.all():
                if mac.assigned_object_type != 'dcim.interface' or not mac.assigned_object:
                    continue
                owners[str(mac.mac_address).upper()].add(mac.assigned_object.device.id)
            self._mac_to_device = owners
        found = set()
        for mac in macs or []:
            found |= self._mac_to_device.get(str(mac).upper(), set())
        found &= set(self._by_id)
        return self._by_id[found.pop()] if len(found) == 1 else None

    def resolve_device(self, name: str):
        """Returns (device, how) for an LLDP system name, or (None, None).
        `how` is 'exact', or a short description of the looser match."""
        device = self._by_name.get(name.strip().lower())
        if device is not None:
            return device, 'exact'

        candidates = self._by_key.get(_name_key(name), [])
        if len(candidates) == 1:
            return candidates[0], 'name differs in case, punctuation, zero padding or -RE suffix'

        tokens = _name_tokens(name)
        if tokens:
            candidates = []
            for candidate in self.devices:
                other = _name_tokens(candidate.name)
                shorter, longer = sorted((tokens, other), key=len)
                if shorter and len(shorter) < len(longer) and longer[-len(shorter):] == shorter:
                    candidates.append(candidate)
            if len(candidates) == 1:
                return candidates[0], 'name is a shortened/lengthened form'

        return None, None

    def mac_owner(self, macs):
        """The one Netbox device these MAC addresses are recorded on, or
        None. Only ever a hint for the report: MAC records go stale when
        hardware is reused, and RouterOS port names are the same on every
        router, so a stale record would cable the wrong device."""
        return self._device_by_mac(macs)

    def port_owner(self, device):
        """The device that holds this device's interfaces in Netbox: the
        master of its virtual chassis (a stacked switch answers LLDP
        under one hostname and Netbox keeps every member's ports on the
        master), otherwise the device itself."""
        chassis = getattr(device, 'virtual_chassis', None)
        master = getattr(chassis, 'master', None) if chassis else None
        if master is not None and master.id != device.id:
            return self._by_id.get(master.id, device)
        return device

    def interfaces(self, device) -> dict:
        """{interface name: interface} for a device, fetched once."""
        if device.id not in self._interfaces:
            self._interfaces[device.id] = {
                iface.name.strip(): iface
                for iface in self._nb_api.dcim.interfaces.filter(device_id=device.id)
            }
        return self._interfaces[device.id]

    @staticmethod
    def is_physical(iface) -> bool:
        if not iface.type:
            return False
        kind = iface.type.value
        return kind not in NON_PHYSICAL_INTERFACE_TYPES and not kind.startswith('ieee802.11')

    def physical_port(self, device, name):
        """The device's physical interface with this exact name (case
        ignored as a fallback), or None."""
        if not name:
            return None
        interfaces = self.interfaces(device)
        iface = interfaces.get(name.strip())
        if iface is None:
            lowered = name.strip().lower()
            matches = [i for n, i in interfaces.items() if n.lower() == lowered]
            iface = matches[0] if len(matches) == 1 else None
        if iface is None or not self.is_physical(iface):
            return None
        return iface

    def advertised_port(self, device, advertised):
        """The physical interface a neighbour's advertised port text
        names, or None. RouterOS prefixes the port with the bridge/bond
        it sits in ('bond_PTN-CE1/sfp-sfpplus5'), so leading '/'-separated
        parts are dropped one at a time until something matches - the
        whole text first, since Junos/NX-OS port names contain slashes
        themselves ('xe-0/1/0')."""
        if not advertised:
            return None
        parts = advertised.strip().split('/')
        for start in range(len(parts)):
            iface = self.physical_port(device, '/'.join(parts[start:]))
            if iface is not None:
                return iface
        return None


def collect_lldp_reports(nb_api, device_credentials, device_filter):
    """Connects to every eligible device and collects its LLDP neighbours.

    Returns (reports, failures): reports is
    {device_id: {'device': nb_device, 'neighbours': [...]}} for devices
    successfully read; failures is [(nb_device, reason)] for the ones
    that could not be, so they can be listed rather than silently
    missing from the result.
    """
    reports = {}
    failures = []
    for device_nb in nb_api.dcim.devices.all():
        if device_nb.role.slug in utils.device_roles_to_ignore:
            continue
        if device_nb.platform is None or device_nb.primary_ip is None:
            continue
        if device_nb.status.value not in utils.acceptable_device_status:
            continue
        if device_filter and device_nb.name not in device_filter:
            continue

        driver_cls = PLATFORM_TO_DRIVER.get(str(device_nb.platform))
        if driver_cls is None:
            continue

        device_ip = str(device_nb.primary_ip).split('/', maxsplit=1)[0]
        try:
            full_dev_creds = {**device_credentials, 'hostname': device_ip}
            device_conn = driver_cls(**full_dev_creds)
            neighbours = [
                n for n in device_conn.get_neighbours()
                if n.source == 'LLDP' and n.interface and n.name
            ]
            del device_conn
        except drivers.base.AuthenticationError:
            failures.append((device_nb, f"{device_ip}: login rejected"))
            continue
        except drivers.base.ConnectError as exc:
            failures.append((device_nb, f"{device_ip}: unreachable ({str(exc)[:120] or 'no response'})"))
            continue
        # pylint: disable=broad-except
        except Exception as exc:
            failures.append((device_nb, f"{device_ip}: {exc.__class__.__name__}: {str(exc)[:120]}"))
            continue

        reports[device_nb.id] = {'device': device_nb, 'neighbours': neighbours}
        logger.info(f"{device_nb.name}: {len(neighbours)} LLDP neighbour entries.")

    return reports, failures


def build_claims(reports, inventory):
    """Turns every LLDP entry into a claim "my physical port X faces
    device B (whose port, if it advertised a real one, is Y)".

    Returns (claims, renamed, missing, shared):
    - claims: {(device_a_id, device_b_id): {local port name: advertised
      interface on B or None}}
    - renamed: {(lldp name, netbox name): how it was matched} for every
      neighbour whose identity was not an exact name match.
    - missing: {lldp name: [(reporting device, local port, Netbox device
      its MAC is recorded on or None)]} for neighbours that match no
      Netbox device at all.
    - shared: [(device id, local port, [neighbour device ids])] for ports
      that hear several neighbours and so back no claim.
    """
    claims = collections.defaultdict(dict)
    renamed = {}
    missing = collections.defaultdict(list)
    peers_by_port = collections.defaultdict(set)
    shared = []

    for report in reports.values():
        device_a = inventory.port_owner(report['device'])
        for neighbour in report['neighbours']:
            local = inventory.physical_port(device_a, neighbour.interface)
            if local is None:
                # A bridge, VLAN, bond or tunnel (or a port Netbox does
                # not know): not something a cable can terminate on.
                continue

            device_b, how = inventory.resolve_device(neighbour.name)
            if device_b is None:
                owner = inventory.mac_owner(neighbour.mac)
                missing[neighbour.name].append(
                    (device_a.name, local.name, owner.name if owner else None)
                )
                continue
            if how != 'exact':
                renamed[(neighbour.name, device_b.name)] = how
            device_b = inventory.port_owner(device_b)
            if device_b.id == device_a.id:
                continue

            remote = inventory.advertised_port(device_b, neighbour.remote_interface)
            ports = claims[(device_a.id, device_b.id)]
            # Several entries for one local port are VLAN sub-interfaces
            # of the same neighbour; keep whichever names a real port.
            if ports.get(local.name) is None:
                ports[local.name] = remote
            peers_by_port[(device_a.id, local.name)].add(device_b.id)

    # A port that hears more than one neighbour sits on a shared segment
    # (a switch in between passing LLDP through) - no single cable can
    # describe it, so it backs no claim at all.
    for (device_id, port), peers in peers_by_port.items():
        if len(peers) < 2:
            continue
        shared.append((device_id, port, sorted(peers)))
        for peer_id in peers:
            claims[(device_id, peer_id)].pop(port, None)
            if not claims[(device_id, peer_id)]:
                del claims[(device_id, peer_id)]

    return claims, renamed, missing, shared


def correlate_links(reports, claims, inventory):
    """Pairs the claims of each two devices into links.

    Returns (links, unresolved):
    - links: [(device_a, iface_a, device_b, iface_b, evidence)] with both
      ends resolved to Netbox interfaces.
    - unresolved: [(device_a, [local ports], device_b, [their ports],
      reason)] for what could not be paired.
    """
    devices = {d.id: d for d in inventory.devices}
    links = []
    unresolved = []
    done = set()

    # Every port each device itself reported a neighbour on.
    busy_ports = collections.defaultdict(set)
    for (id_a, _id_b), ports in claims.items():
        busy_ports[id_a].update(ports)

    for (id_a, id_b) in list(claims):
        pair = tuple(sorted((id_a, id_b)))
        if pair in done:
            continue
        done.add(pair)
        id_a, id_b = pair
        device_a, device_b = devices[id_a], devices[id_b]
        from_a = dict(claims.get((id_a, id_b), {}))   # A's port -> B's interface or None
        from_b = dict(claims.get((id_b, id_a), {}))   # B's port -> A's interface or None

        # Every (A port, B port) pair some advertised port name supports.
        support = collections.defaultdict(set)
        for port_a, iface_b in from_a.items():
            if iface_b is not None:
                support[(port_a, iface_b.name.strip())].add(device_a.name)
        for port_b, iface_a in from_b.items():
            if iface_a is not None:
                support[(iface_a.name.strip(), port_b)].add(device_b.name)

        # A port may only be in one link; contradictory pairs are dropped.
        used_a = collections.Counter(a for a, _ in support)
        used_b = collections.Counter(b for _, b in support)
        paired = {}
        for (port_a, port_b), sources in support.items():
            if used_a[port_a] > 1 or used_b[port_b] > 1:
                continue
            seen_a = port_a in from_a
            seen_b = port_b in from_b
            if seen_a and seen_b:
                evidence = 'both ends report it, ports confirmed by advertised port name'
            else:
                silent = id_b if seen_a else id_a
                silent_port = port_b if seen_a else port_a
                if silent_port in busy_ports.get(silent, ()):
                    # The silent end does report that port - facing
                    # some other device. Contradicted, not confirmed.
                    continue
                why = (
                    'the other end could not be read' if silent not in reports
                    else 'the other end reports no LLDP neighbour there'
                )
                evidence = (
                    f"reported by {', '.join(sorted(sources))} only ({why}), "
                    "advertised port name is a real interface"
                )
            paired[(port_a, port_b)] = evidence

        left_a = [p for p in from_a if p not in {a for a, _ in paired}]
        left_b = [p for p in from_b if p not in {b for _, b in paired}]
        if len(left_a) == 1 and len(left_b) == 1:
            paired[(left_a[0], left_b[0])] = 'both ends report it, the only unpaired link between them'
            left_a, left_b = [], []

        for (port_a, port_b), evidence in paired.items():
            iface_a = inventory.physical_port(device_a, port_a)
            iface_b = inventory.physical_port(device_b, port_b)
            if iface_a is None or iface_b is None:
                continue
            links.append((device_a, iface_a, device_b, iface_b, evidence))

        if left_a or left_b:
            if left_a and left_b:
                reason = 'parallel links - cannot tell which port pairs with which'
            elif (id_b if left_a else id_a) not in reports:
                reason = "other end could not be read and did not advertise a usable port name"
            else:
                reason = 'other end does not report it back'
            unresolved.append((device_a, left_a, device_b, left_b, reason))

    return links, unresolved


def _cable_peers(iface):
    """Ids of the interfaces at the far end of an interface's cable."""
    return {
        peer.id for peer in (getattr(iface, 'link_peers', None) or [])
        if getattr(iface, 'link_peers_type', None) == 'dcim.interface'
    }


def apply_links(nb_api, links, commit: bool):
    """Reports (and, if commit, creates) a Cable for each link whose two
    interfaces are both currently uncabled. Returns (created, conflicts)."""
    created = 0
    conflicts = []
    for device_a, iface_a, device_b, iface_b, evidence in sorted(
        links, key=lambda l: (l[0].name, l[1].name),
    ):
        label = f"{device_a.name}/{iface_a.name} <-> {device_b.name}/{iface_b.name}"

        if iface_a.cable or iface_b.cable:
            if iface_b.id in _cable_peers(iface_a):
                print(f"OK (already cabled)   {label}")
            else:
                conflicts.append((label, iface_a, iface_b))
            continue

        if not commit:
            print(f"WOULD CREATE          {label}   [{evidence}]")
            continue

        try:
            nb_api.dcim.cables.create(
                a_terminations=[{'object_type': 'dcim.interface', 'object_id': iface_a.id}],
                b_terminations=[{'object_type': 'dcim.interface', 'object_id': iface_b.id}],
                status='connected',
                description=f"LLDP: {evidence}"[:200],
            )
            print(f"CREATED               {label}   [{evidence}]")
            created += 1
        except pynetbox.RequestError as exc:
            print(f"FAILED ({exc})   {label}")

    return created, conflicts


def _describe_cable_end(iface):
    """Where Netbox currently says an interface's cable goes."""
    if not iface.cable:
        return 'no cable'
    peers = getattr(iface, 'link_peers', None) or []
    if not peers:
        return 'a cable with nothing on the far end'
    names = []
    for peer in peers:
        owner = getattr(peer, 'device', None) or getattr(peer, 'circuit', None)
        names.append(f"{owner}/{getattr(peer, 'name', None) or peer}")
    return ', '.join(names)


def main():
    """Entry point."""
    args = parse_arguments()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format=LOGGING_FORMAT,
    )
    logging.getLogger('ncclient').setLevel(logging.ERROR)
    logging.getLogger('librouteros').setLevel(logging.ERROR)
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)

    nb_api = pynetbox.api(
        os.environ.get('NB_URL'),
        token=os.environ.get('NB_TOKEN'),
        threading=True,
    )
    device_credentials = utils.parse_device_parameters()

    inventory = Inventory(nb_api)
    reports, failures = collect_lldp_reports(nb_api, device_credentials, args.netbox_device)
    claims, renamed, missing, shared = build_claims(reports, inventory)
    links, unresolved = correlate_links(reports, claims, inventory)

    print(f"\n{len(reports)} device(s) read, {len(failures)} could not be read; "
          f"{len(links)} link(s) resolved, {len(unresolved)} device pair(s) unresolved.\n")

    if not args.commit:
        print("--- DRY RUN (pass --commit to actually create cables) ---")
    created, conflicts = apply_links(nb_api, links, args.commit)

    if conflicts:
        print("\n--- Conflicts (Netbox already has a different cable on one of these ports) ---")
        for label, iface_a, iface_b in conflicts:
            print(f"  LLDP: {label}")
            print(f"    Netbox: {iface_a.device.name}/{iface_a.name} -> {_describe_cable_end(iface_a)}; "
                  f"{iface_b.device.name}/{iface_b.name} -> {_describe_cable_end(iface_b)}")

    if unresolved:
        print("\n--- Unresolved (needs manual review) ---")
        for device_a, ports_a, device_b, ports_b, reason in sorted(
            unresolved, key=lambda u: (u[0].name, u[2].name),
        ):
            print(f"  {device_a.name}{sorted(ports_a)} <-> {device_b.name}{sorted(ports_b)}: {reason}")

    if shared:
        names = {d.id: d.name for d in inventory.devices}
        print("\n--- Ports that hear several neighbours (a switch in between; not cabled) ---")
        for device_id, port, peers in sorted(shared, key=lambda x: (names[x[0]], x[1])):
            print(f"  {names[device_id]}/{port}: {', '.join(sorted(names[p] for p in peers))}")

    if missing:
        print("\n--- Neighbours with no matching Netbox device ---")
        for name in sorted(missing):
            seen = ', '.join(sorted({f"{dev}/{port}" for dev, port, _ in missing[name]}))
            owners = sorted({owner for _, _, owner in missing[name] if owner})
            hint = f" (its MAC is recorded on Netbox device {', '.join(owners)})" if owners else ''
            print(f"  {name}: seen from {seen}{hint}")

    if renamed:
        print("\n--- Neighbours whose hostname differs from their Netbox name ---")
        for (lldp_name, nb_name), how in sorted(renamed.items()):
            print(f"  '{lldp_name}' is Netbox device '{nb_name}' ({how})")

    if failures:
        print("\n--- Devices that could not be read ---")
        for device_nb, reason in sorted(failures, key=lambda f: f[0].name):
            print(f"  {device_nb.name} ({device_nb.platform}): {reason}")

    if args.commit:
        print(f"\nCreated {created} cable(s).")


if __name__ == "__main__":
    main()
