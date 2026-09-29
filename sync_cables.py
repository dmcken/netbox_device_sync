#!/usr/bin/python3
'''Build real Netbox Cable objects from live LLDP neighbour data.

Connects to every Netbox device whose platform has LLDP support (Junos,
RouterOS), collects each one's LLDP neighbour table, then correlates the
two sides of every reported link with each other before trusting it:

- A remote port name reported directly by LLDP (Junos exposes only a
  free-text *description* someone configured on that port, not its
  real ID; a single physical link can also show up as several entries
  differing only in that text, one per VLAN sub-interface riding the
  same trunk) is never trusted on its own.
- A link is only "confirmed" when device A reports seeing device B on
  local port X, AND device B independently reports seeing device A
  back on local port Y - each side's own reported local port is
  authoritative, the far side's description of it is not.
- A link touching a device we have no driver for (e.g. a Pica8 switch),
  or that's asymmetric (only one side reports it), or ambiguous
  (either side has more than one candidate local port for the same
  peer - can't tell which pairs with which), is left for manual review,
  never guessed at.
- A candidate whose local interface already has a cable, on either end,
  is left alone - this script only ever fills in gaps, never touches
  existing cable data.

Defaults to a dry-run report of what it would do; pass --commit to
actually create the confirmed cables.
'''

# System imports
import argparse
import collections
import logging
import os

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


def collect_lldp_reports(nb_api, device_credentials, device_filter):
    '''Connects to every eligible device and collects its LLDP neighbours.

    Returns {device_id: {'device': nb_device, 'neighbours': [...]}} for
    devices successfully connected to. A connection failure is logged
    and that device is simply left out - it'll surface any links to it
    as unconfirmed rather than stopping the whole run.

    Each device's neighbours are deduped by (interface, remote mac): one
    physical port reporting several VLAN sub-interfaces of the same
    remote chassis is one physical link, not several.
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
            neighbours = [
                n for n in device_conn.get_neighbours() if n.source == 'LLDP'
            ]
            del device_conn
        except drivers.base.ConnectError as exc:
            logger.warning(f"Could not connect to {device_nb.name} ({device_ip}): {exc}")
            continue
        # pylint: disable=broad-except
        except Exception as exc:
            logger.warning(f"Error collecting LLDP from {device_nb.name}: {exc.__class__.__name__}: {exc}")
            continue

        deduped = {}
        for n in neighbours:
            if not n.interface:
                continue
            key = (n.interface.strip(), tuple(n.mac or []))
            deduped[key] = n
        reports[device_nb.id] = {'device': device_nb, 'neighbours': list(deduped.values())}
        logger.info(f"{device_nb.name}: {len(deduped)} LLDP neighbour(s) after dedup.")

    return reports


def correlate_links(reports):
    '''Cross-correlates every device's LLDP report against its peers'.

    Returns (confirmed, unconfirmed, ambiguous):
    - confirmed: list of (device_a, iface_a, device_b, iface_b)
    - unconfirmed: list of (device_a, iface_a, remote_name) - the far
      side wasn't collected, or didn't report this device back.
    - ambiguous: list of (device_a, iface_a, remote_name, reason) - more
      than one candidate on either side for the same device pair.
    '''
    by_name = {r['device'].name.lower(): r for r in reports.values()}

    confirmed = []
    unconfirmed = []
    ambiguous = []
    seen_pairs = set()

    for report in reports.values():
        device_a = report['device']

        # Group this device's own neighbours by which peer device they
        # claim to be - more than one local interface pointing at the
        # same peer means a parallel/aggregate link we can't safely
        # auto-pair without risking a crossed cable.
        by_peer = collections.defaultdict(list)
        for n in report['neighbours']:
            by_peer[n.name.lower()].append(n)

        for peer_name, entries in by_peer.items():
            # A device pair only needs resolving once, from whichever
            # side we reach it first.
            if (device_a.id, peer_name) in seen_pairs:
                continue

            peer_report = by_name.get(peer_name)
            if peer_report is None:
                for n in entries:
                    unconfirmed.append((device_a, n.interface, n.name))
                continue
            device_b = peer_report['device']
            seen_pairs.add((device_a.id, peer_name))
            seen_pairs.add((device_b.id, device_a.name.lower()))

            back_entries = [
                n for n in peer_report['neighbours']
                if n.name.lower() == device_a.name.lower()
            ]

            if len(entries) > 1 or len(back_entries) > 1:
                ambiguous.append((
                    device_a, [n.interface for n in entries],
                    device_b, [n.interface for n in back_entries],
                ))
                continue
            if not back_entries:
                unconfirmed.append((device_a, entries[0].interface, device_b.name))
                continue

            confirmed.append((device_a, entries[0].interface, device_b, back_entries[0].interface))

    return confirmed, unconfirmed, ambiguous


def resolve_interface(nb_api, device_nb, iface_name):
    '''Looks up a device's interface by name, tolerating stray whitespace
    (a known RouterOS quirk - see sync.py's own interface sync fix).
    Returns None (never guesses) if it's missing or ambiguous.
    '''
    matches = list(nb_api.dcim.interfaces.filter(
        device_id=device_nb.id, name=iface_name.strip(),
    ))
    if len(matches) != 1:
        return None
    return matches[0]


def apply_confirmed_links(nb_api, confirmed, commit: bool):
    '''Reports (and, if commit, creates) a Cable for each confirmed link
    whose two interfaces both resolve in Netbox and are both currently
    uncabled. Anything else is reported and left alone.
    '''
    created = 0
    for device_a, iface_a_name, device_b, iface_b_name in confirmed:
        iface_a = resolve_interface(nb_api, device_a, iface_a_name)
        iface_b = resolve_interface(nb_api, device_b, iface_b_name)

        label = f"{device_a.name}/{iface_a_name} <-> {device_b.name}/{iface_b_name}"

        if iface_a is None or iface_b is None:
            print(f"SKIP (interface not found in Netbox)  {label}")
            continue
        if iface_a.cable or iface_b.cable:
            print(f"SKIP (already cabled)                 {label}")
            continue

        if not commit:
            print(f"WOULD CREATE                          {label}")
            continue

        try:
            nb_api.dcim.cables.create(
                a_terminations=[{'object_type': 'dcim.interface', 'object_id': iface_a.id}],
                b_terminations=[{'object_type': 'dcim.interface', 'object_id': iface_b.id}],
                status='connected',
            )
            print(f"CREATED                                {label}")
            created += 1
        except pynetbox.RequestError as exc:
            print(f"FAILED ({exc})                        {label}")

    return created


def main():
    '''Entry point.'''
    args = parse_arguments()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format=LOGGING_FORMAT,
    )
    logging.getLogger('ncclient').setLevel(logging.ERROR)
    logging.getLogger('librouteros').setLevel(logging.ERROR)
    logging.getLogger('paramiko.transport').setLevel(logging.ERROR)

    nb_api = pynetbox.api(
        os.environ.get('NB_URL'),
        token=os.environ.get('NB_TOKEN'),
        threading=True,
    )
    device_credentials = utils.parse_device_parameters()

    reports = collect_lldp_reports(nb_api, device_credentials, args.netbox_device)
    confirmed, unconfirmed, ambiguous = correlate_links(reports)

    print(f"\n{len(confirmed)} confirmed link(s), "
          f"{len(unconfirmed)} unconfirmed, {len(ambiguous)} ambiguous.\n")

    if not args.commit:
        print("--- DRY RUN (pass --commit to actually create cables) ---")
    created = apply_confirmed_links(nb_api, confirmed, args.commit)

    if unconfirmed:
        print("\n--- Unconfirmed (only one side reported this link) ---")
        for device_a, iface_a, remote_name in unconfirmed:
            print(f"  {device_a.name}/{iface_a} -> {remote_name} (not confirmed back)")

    if ambiguous:
        print("\n--- Ambiguous (multiple candidate ports - needs manual review) ---")
        for device_a, ifaces_a, device_b, ifaces_b in ambiguous:
            print(f"  {device_a.name}{ifaces_a} <-> {device_b.name}{ifaces_b}")

    if args.commit:
        print(f"\nCreated {created} cable(s).")


if __name__ == "__main__":
    main()
