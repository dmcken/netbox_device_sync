#!/usr/bin/python3
'''Build real NetBox L2VPN objects from live EoIP tunnel data -- the
overlay-tunnel counterpart to sync_cables.py's physical LLDP-based
cabling.

Connects to every NetBox RouterOS device, collects its EoIP tunnel
interfaces (drivers.routeros.RouterOS.get_eoip_tunnels()), correlates
each tunnel's remote_address + tunnel_id against every other
collected device's own tunnels to pair up two-sided tunnels (see
correlate_tunnels()), then GROUPS individual legs into the circuits
they actually belong to (see group_into_circuits()):

- A plain point-to-point tunnel between two sites that each only have
  this one leg becomes a VPWS (point-to-point) L2VPN, as before.
- This fleet's convention for a multipoint/hub/ring circuit (e.g.
  DAN-CE3/4/5's DAN-SVR ring to their 3 Proxmox servers, or SHP-CE1's
  customer hub bridging several spokes) is several separate
  point-to-point EoIP tunnels all sharing one local bridge per
  participating router, not one actual multipoint protocol on the
  wire -- but the *circuit* itself is multipoint, so every leg
  touching a shared bridge merges into one VPLS L2VPN with one
  termination per real endpoint, rather than being modeled as several
  disconnected point-to-point objects.
- A tunnel that isn't locally bridged at all (routed, e.g. the
  TransGrid/NBN WAN-circuit overlays) never merges with anything --
  each stays its own site, since there's no shared flood domain to
  merge on.

Safe to re-run: an interface already carrying an L2VPNTermination is
never touched again, BUT a circuit that already exists in NetBox
(found via any one of its already-terminated interfaces) and has
grown a brand new leg since the last run gets that leg ADDED as a new
termination on the existing L2VPN, rather than skipped or duplicated
-- this is deliberately the common case this tool is built around:
adding a new endpoint to an existing WAN.

Defaults to a dry-run report of what it would do; pass --commit to
actually create/extend the L2VPNs.
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
import drivers.routeros
import utils

dotenv.load_dotenv()

LOGGING_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logger = logging.getLogger(__name__)

# EoIP is a MikroTik/RouterOS-specific tunnel type -- no other driver
# has (or needs) a get_eoip_tunnels().
PLATFORM_TO_DRIVER = {
    'RouterOS': drivers.routeros.RouterOS,
}

REASON_LABELS = {
    'orphaned': 'orphaned (no reciprocal tunnel)',
    'unresolved': 'remote address unresolved',
}


def parse_arguments() -> argparse.Namespace:
    '''Parse CLI arguments.'''
    parser = argparse.ArgumentParser(
        prog="EoIP -> L2VPN sync",
        description=__doc__,
    )
    parser.add_argument(
        '-n', '--netbox-device', nargs='+', default=[],
        help=(
            "Only pull EoIP data from these NetBox devices. A tunnel to a "
            "device outside this scope will show as single-sided (that "
            "side's data wasn't collected), not wrongly treated as orphaned."
        ),
    )
    parser.add_argument(
        '--commit', action='store_true',
        help="USE WITH CAUTION. Actually create/extend the L2VPNs in "
             "NetBox. Without this, only a report is printed.",
    )
    parser.add_argument(
        '-d', '--debug', action='store_true', help="Verbose logging.",
    )
    return parser.parse_args()


def collect_eoip_reports(nb_api, device_credentials, device_filter):
    '''Connects to every eligible RouterOS device and collects its EoIP
    tunnels.

    Returns {device_id: {'device': nb_device, 'tunnels': [...]}} for
    devices successfully connected to. A connection failure is logged
    and that device is simply left out -- any tunnel pointing at it
    surfaces as single-sided rather than stopping the whole run.
    '''
    reports = {}
    devices = nb_api.dcim.devices.all()
    for device_nb in devices:
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
            tunnels = device_conn.get_eoip_tunnels()
            del device_conn
        except drivers.base.ConnectError as exc:
            logger.warning(f"Could not connect to {device_nb.name} ({device_ip}): {exc}")
            continue
        # pylint: disable=broad-except
        except Exception as exc:
            logger.warning(f"Error collecting EoIP tunnels from {device_nb.name}: {exc.__class__.__name__}: {exc}")
            continue

        reports[device_nb.id] = {'device': device_nb, 'tunnels': tunnels}
        logger.info(f"{device_nb.name}: {len(tunnels)} EoIP tunnel(s).")

    return reports


def resolve_device_by_ip(nb_api, ip_address):
    '''The NetBox device whose interface currently holds `ip_address`,
    or None if it isn't assigned to any interface NetBox knows about
    (not necessarily an error -- a remote tunnel endpoint can be a
    device simply not tracked in NetBox at all).
    '''
    if ip_address is None:
        return None
    matches = list(nb_api.ipam.ip_addresses.filter(address=str(ip_address)))
    for match in matches:
        assigned = match.assigned_object
        if assigned is not None and hasattr(assigned, 'device') and assigned.device:
            return assigned.device
    return None


def correlate_tunnels(nb_api, reports):
    '''Cross-correlates every device's EoIP report against its peers'.

    Returns (confirmed, single_sided):
    - confirmed: list of (device_a, iface_a, device_b, iface_b, tunnel_id)
      -- iface_a/iface_b are drivers.base.EoipTunnel, not yet resolved
      to real NetBox interfaces (see resolve_interface()).
    - single_sided: list of (device_a, iface_a, tunnel_id, remote_address,
      reason) -- reason is one of 'orphaned' (remote device was
      collected, but reports no tunnel back), 'out-of-scope' (remote
      device exists in NetBox but wasn't collected from -- e.g. a
      customer CPE, or simply outside --netbox-device), or
      'unresolved' (remote_address doesn't match any NetBox device).
    '''
    confirmed = []
    single_sided = []
    seen = set()  # (device_id, interface) already placed into confirmed

    for report in reports.values():
        device_a = report['device']
        for tunnel_a in report['tunnels']:
            if (device_a.id, tunnel_a.interface) in seen:
                continue

            remote_device = resolve_device_by_ip(nb_api, tunnel_a.remote_address)
            if remote_device is None:
                single_sided.append((
                    device_a, tunnel_a.interface, tunnel_a.tunnel_id,
                    tunnel_a.remote_address, 'unresolved',
                ))
                continue

            peer_report = reports.get(remote_device.id)
            if peer_report is None:
                single_sided.append((
                    device_a, tunnel_a.interface, tunnel_a.tunnel_id,
                    tunnel_a.remote_address, 'out-of-scope',
                ))
                continue

            match = next(
                (t for t in peer_report['tunnels'] if t.tunnel_id == tunnel_a.tunnel_id),
                None,
            )
            if match is None:
                single_sided.append((
                    device_a, tunnel_a.interface, tunnel_a.tunnel_id,
                    tunnel_a.remote_address, 'orphaned',
                ))
                continue

            confirmed.append((device_a, tunnel_a.interface, remote_device, match.interface, tunnel_a.tunnel_id))
            seen.add((device_a.id, tunnel_a.interface))
            seen.add((remote_device.id, match.interface))

    return confirmed, single_sided


def resolve_interface(nb_api, device_nb, iface_name):
    '''Looks up a device's interface by name, and its `bridge` field if
    any. Returns None (never guesses) if it's missing or ambiguous.'''
    matches = list(nb_api.dcim.interfaces.filter(
        device_id=device_nb.id, name=iface_name.strip(),
    ))
    if len(matches) != 1:
        return None
    return matches[0]


class _UnionFind:
    '''Minimal disjoint-set over arbitrary hashable keys, used to
    collapse individual EoIP legs into the circuits they actually
    belong to -- see group_into_circuits().'''

    def __init__(self):
        self._parent = {}

    def find(self, key):
        self._parent.setdefault(key, key)
        while self._parent[key] != key:
            self._parent[key] = self._parent[self._parent[key]]
            key = self._parent[key]
        return key

    def union(self, a, b):
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self._parent[root_a] = root_b


def _site_of(nb_api, device, resolved_iface):
    '''(device_id, bridge_name) identifying the local flood domain a
    resolved NetBox interface belongs to -- the unit circuit grouping
    actually operates on. A tunnel with no local bridge (routed, not
    bridged) gets a key unique to itself instead, so it never merges
    with anything -- there's no shared flood domain to merge on.
    '''
    if resolved_iface.bridge:
        return (device.id, str(resolved_iface.bridge))
    return ('unbridged', resolved_iface.id)


def group_into_circuits(nb_api, confirmed, single_sided):
    '''Resolves every leg's interfaces in NetBox, then collapses them
    into the circuits they actually belong to (see this module's own
    docstring for the merge rule). A leg whose interface doesn't
    resolve in NetBox at all is dropped (reported separately by the
    caller as unresolvable), same as before.

    Returns a list of circuits: {'type': 'vpws' | 'vpls',
    'members': [(device, interface), ...], 'tunnel_id': int | None,
    'reasons': Counter} -- members is already deduplicated by
    interface id (a device can touch a circuit via more than one leg,
    e.g. DAN-CE4 in the DAN-SVR ring).
    '''
    resolved_confirmed = []
    resolved_single = []
    unresolvable = []

    for device_a, iface_a, device_b, iface_b, tunnel_id in confirmed:
        resolved_a = resolve_interface(nb_api, device_a, iface_a)
        resolved_b = resolve_interface(nb_api, device_b, iface_b)
        if resolved_a is None:
            unresolvable.append(f"{device_a.name}/{iface_a}")
        if resolved_b is None:
            unresolvable.append(f"{device_b.name}/{iface_b}")
        if resolved_a is None or resolved_b is None:
            continue
        resolved_confirmed.append((device_a, resolved_a, device_b, resolved_b, tunnel_id))

    for device_a, iface_a, tunnel_id, remote_address, reason in single_sided:
        resolved_a = resolve_interface(nb_api, device_a, iface_a)
        if resolved_a is None:
            unresolvable.append(f"{device_a.name}/{iface_a}")
            continue
        resolved_single.append((device_a, resolved_a, tunnel_id, remote_address, reason))

    uf = _UnionFind()
    site_legs = collections.defaultdict(list)  # site -> [('confirmed'|'single', idx)]

    for idx, (device_a, iface_a, device_b, iface_b, tunnel_id) in enumerate(resolved_confirmed):
        site_a = _site_of(nb_api, device_a, iface_a)
        site_b = _site_of(nb_api, device_b, iface_b)
        uf.union(site_a, site_b)
        site_legs[site_a].append(('confirmed', idx))
        if site_b != site_a:
            site_legs[site_b].append(('confirmed', idx))

    for idx, (device_a, iface_a, tunnel_id, remote_address, reason) in enumerate(resolved_single):
        site_a = _site_of(nb_api, device_a, iface_a)
        site_legs[site_a].append(('single', idx))

    circuits_by_root = collections.defaultdict(set)
    for site, entries in site_legs.items():
        root = uf.find(site)
        for kind, idx in entries:
            circuits_by_root[root].add((kind, idx))

    circuits = []
    for idents in circuits_by_root.values():
        confirmed_members = sorted({i for kind, i in idents if kind == 'confirmed'})
        single_members = sorted({i for kind, i in idents if kind == 'single'})
        leg_count = len(confirmed_members) + len(single_members)

        members = {}  # interface id -> (device, interface)
        for i in confirmed_members:
            device_a, iface_a, device_b, iface_b, _ = resolved_confirmed[i]
            members[iface_a.id] = (device_a, iface_a)
            members[iface_b.id] = (device_b, iface_b)
        for i in single_members:
            device_a, iface_a, _, _, _ = resolved_single[i]
            members[iface_a.id] = (device_a, iface_a)

        reasons = collections.Counter(
            resolved_single[i][4] for i in single_members if resolved_single[i][4] in REASON_LABELS
        )

        tunnel_id = None
        if leg_count == 1:
            tunnel_id = (
                resolved_confirmed[confirmed_members[0]][4] if confirmed_members
                else resolved_single[single_members[0]][2]
            )

        circuits.append({
            'type': 'vpls' if leg_count > 1 else 'vpws',
            'members': list(members.values()),
            'tunnel_id': tunnel_id,
            'reasons': reasons,
        })

    return circuits, unresolvable


def _slugify(text: str) -> str:
    return re.sub(r'[^a-zA-Z0-9]+', '-', text).strip('-').lower()[:100]


def _circuit_name(circuit):
    '''Best name for a circuit.

    Exactly 2 members (VPWS, whether bridged or routed) is always
    named by its device pair, with the bridge name (if any) just a
    parenthetical note -- never by bridge name alone, since this
    fleet reuses generic local bridge names (above all "trunk", a
    router's own main VLAN bridge) completely independently across
    unrelated routers. Naming purely by a shared bridge name would
    collide two completely unrelated point-to-point circuits onto the
    one display name (and the one NetBox slug).

    A real multipoint circuit (3+ members) is named by the one bridge
    name shared across every member, if there is one -- this really
    is this fleet's own convention for a multipoint circuit (e.g.
    "DAN-SVR", "virtual-customers": the same bridge name, deliberately
    reused, on every participating router) -- else by the hub
    device/bridge (whichever site has the most members touching it,
    e.g. SHP-CE1's customer hub, where each spoke's own local bridge
    is named differently from SHP-CE1's and from each other).
    '''
    names = sorted({device.name for device, _ in circuit['members']})
    suffix = f" (id {circuit['tunnel_id']})" if circuit['tunnel_id'] is not None else ""

    if len(circuit['members']) == 2:
        bridges = {str(iface.bridge) for _, iface in circuit['members'] if iface.bridge}
        note = f" ({next(iter(bridges))})" if len(bridges) == 1 else ""
        return f"EoIP: {names[0]} <-> {names[1]}{note}{suffix}"

    bridge_names = {str(iface.bridge) for _, iface in circuit['members'] if iface.bridge}
    if len(bridge_names) == 1:
        return f"EoIP: {next(iter(bridge_names))}"

    site_counts = collections.Counter(
        (device.name, str(iface.bridge)) for device, iface in circuit['members'] if iface.bridge
    )
    if site_counts:
        (device_name, bridge_name), _ = site_counts.most_common(1)[0]
        return f"EoIP: {device_name}/{bridge_name} hub"

    return f"EoIP: {', '.join(names)}{suffix}"


def _circuit_description(circuit):
    notes = [f"{count} {REASON_LABELS[reason]}" for reason, count in circuit['reasons'].items()]
    return '; '.join(notes)


def _find_existing_l2vpn(nb_api, members):
    '''If any member interface in this circuit already has an
    L2VPNTermination, return that termination's L2VPN -- this circuit
    already exists in NetBox (fully or partially), so a brand new
    member found this run should be ADDED to it, not create a
    duplicate L2VPN. None if nothing in this circuit has ever synced.
    '''
    for _, iface in members:
        existing = list(nb_api.vpn.l2vpn_terminations.filter(
            assigned_object_type='dcim.interface', assigned_object_id=iface.id,
        ))
        if existing:
            return existing[0].l2vpn
    return None


def _already_terminated(nb_api, interface) -> bool:
    existing = list(nb_api.vpn.l2vpn_terminations.filter(
        assigned_object_type='dcim.interface', assigned_object_id=interface.id,
    ))
    return bool(existing)


def apply_circuits(nb_api, circuits, commit: bool):
    '''Reports (and, if commit, creates/extends) one L2VPN per circuit.
    A circuit already (fully or partially) in NetBox gets any new
    member added as a new termination on the existing L2VPN -- the
    common case this tool is built around: adding a new endpoint to
    an existing WAN, not creating a parallel one.
    '''
    created = 0
    extended = 0
    for circuit in circuits:
        label = _circuit_name(circuit)
        existing_l2vpn = _find_existing_l2vpn(nb_api, circuit['members'])
        new_members = [
            (device, iface) for device, iface in circuit['members']
            if not _already_terminated(nb_api, iface)
        ]

        if existing_l2vpn is not None:
            if not new_members:
                print(f"SKIP (already fully synced)                 {label}")
                continue
            member_desc = ', '.join(f"{d.name}/{i.name}" for d, i in new_members)
            if not commit:
                print(f"WOULD ADD {len(new_members)} endpoint(s) to '{existing_l2vpn.name}': {member_desc}")
                continue
            try:
                for device, iface in new_members:
                    nb_api.vpn.l2vpn_terminations.create(
                        l2vpn=existing_l2vpn.id, assigned_object_type='dcim.interface',
                        assigned_object_id=iface.id,
                    )
                print(f"ADDED {len(new_members)} endpoint(s) to '{existing_l2vpn.name}': {member_desc}")
                extended += 1
            except pynetbox.RequestError as exc:
                print(f"FAILED to extend '{existing_l2vpn.name}' ({exc}): {member_desc}")
            continue

        # Brand new circuit.
        member_desc = ', '.join(f"{d.name}/{i.name}" for d, i in circuit['members'])
        if not commit:
            print(f"WOULD CREATE ({circuit['type']}, {len(circuit['members'])} endpoint(s))  {label}: {member_desc}")
            continue
        try:
            l2vpn = nb_api.vpn.l2vpns.create(
                name=label, slug=_slugify(label), type=circuit['type'],
                identifier=circuit['tunnel_id'], description=_circuit_description(circuit),
            )
            for device, iface in circuit['members']:
                nb_api.vpn.l2vpn_terminations.create(
                    l2vpn=l2vpn.id, assigned_object_type='dcim.interface', assigned_object_id=iface.id,
                )
            print(f"CREATED ({circuit['type']}, {len(circuit['members'])} endpoint(s))  {label}: {member_desc}")
            created += 1
        except pynetbox.RequestError as exc:
            print(f"FAILED ({exc})  {label}")

    return created, extended


def main():
    '''Entry point.'''
    args = parse_arguments()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format=LOGGING_FORMAT,
    )
    logging.getLogger('librouteros').setLevel(logging.ERROR)
    logging.getLogger('paramiko.transport').setLevel(logging.ERROR)

    nb_api = pynetbox.api(
        os.environ.get('NB_URL'),
        token=os.environ.get('NB_TOKEN'),
        threading=True,
    )
    device_credentials = utils.parse_device_parameters()

    reports = collect_eoip_reports(nb_api, device_credentials, args.netbox_device)
    confirmed, single_sided = correlate_tunnels(nb_api, reports)
    circuits, unresolvable = group_into_circuits(nb_api, confirmed, single_sided)

    vpws_count = sum(1 for c in circuits if c['type'] == 'vpws')
    vpls_count = sum(1 for c in circuits if c['type'] == 'vpls')
    print(f"\n{len(circuits)} circuit(s): {vpws_count} point-to-point (VPWS), "
          f"{vpls_count} multipoint (VPLS). {len(unresolvable)} leg(s) couldn't "
          f"be resolved to a NetBox interface at all.\n")

    if not args.commit:
        print("--- DRY RUN (pass --commit to actually create/extend L2VPNs) ---")

    created, extended = apply_circuits(nb_api, circuits, args.commit)

    if unresolvable:
        print("\n--- Interfaces not found in NetBox (device-sync gap, not this tool's job) ---")
        for entry in unresolvable:
            print(f"  {entry}")

    if args.commit:
        print(f"\nCreated {created} new L2VPN(s), extended {extended} existing one(s).")


if __name__ == "__main__":
    main()
