#!/usr/bin/python3
'''Build real NetBox L2VPN (type vpws) objects from live EoIP tunnel
data -- the overlay-tunnel counterpart to sync_cables.py's physical
LLDP-based cabling.

Connects to every NetBox RouterOS device, collects its EoIP tunnel
interfaces (drivers.routeros.RouterOS.get_eoip_tunnels()), then
correlates each tunnel's remote_address + tunnel_id against every
other collected device's own tunnels before trusting it:

- A tunnel is "confirmed" (two-sided) only when device A reports a
  tunnel to device B's address with tunnel-id N, AND device B
  independently reports one back to device A's address with the same
  tunnel-id N. remote_address alone can't pair two interfaces: a
  device commonly runs several unrelated EoIP tunnels to the same
  remote address (one public IP multiplexing many tunnels via
  distinct tunnel IDs), so tunnel_id has to agree too.
- A tunnel whose remote_address resolves to a NetBox device that
  wasn't collected from (not RouterOS, not reachable, or simply
  outside --netbox-device scope -- e.g. a customer's own CPE) is
  "single-sided": only our own side is documented, same as this
  fleet's existing customer-facing EoIP tunnels.
- A tunnel whose remote_address resolves to a device that WAS
  collected from, but that device reports no reciprocal tunnel back,
  is flagged "orphaned" -- also recorded single-sided, but called out
  separately since it's more likely stale leftover config than a
  real one-ended tunnel (a confirmed live example: two EoIP
  interfaces pointing at devices with no tunnel configured back at
  all, both disabled/not running).
- A tunnel whose remote_address doesn't resolve to any NetBox device
  at all is "unresolved" -- recorded single-sided with the bare IP
  noted, since there's nothing in NetBox to terminate the far end on.
- An interface that already has an L2VPNTermination, on either end,
  is left alone -- this script only ever fills in gaps, never touches
  existing L2VPN data, so it's safe to re-run.

Defaults to a dry-run report of what it would do; pass --commit to
actually create the L2VPNs/terminations.
'''

# System imports
import argparse
import logging
import os

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
        help="USE WITH CAUTION. Actually create the L2VPNs/terminations in "
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
    '''Looks up a device's interface by name. Returns None (never
    guesses) if it's missing or ambiguous.'''
    matches = list(nb_api.dcim.interfaces.filter(
        device_id=device_nb.id, name=iface_name.strip(),
    ))
    if len(matches) != 1:
        return None
    return matches[0]


def _already_terminated(nb_api, interface) -> bool:
    '''True if this interface already has an L2VPNTermination -- the
    idempotency check that makes re-running this script safe (never
    creates a second L2VPN over the same tunnel interface).'''
    existing = list(nb_api.vpn.l2vpn_terminations.filter(
        assigned_object_type='dcim.interface', assigned_object_id=interface.id,
    ))
    return bool(existing)


def _l2vpn_name(device_a, device_b=None, label=None, tunnel_id=None):
    '''Human-readable, globally-unique L2VPN name. tunnel_id is always
    appended (not just when a collision happens) -- two independent
    tunnels between the exact same device pair, each with their own
    ID, are a real and already-confirmed-live configuration (DAN-CE4
    <-> DAN-CE5 runs both a DAN-SVR mesh leg and a separate full-trunk
    extension), so a name built from the device pair alone isn't
    actually unique.'''
    suffix = f" (id {tunnel_id})" if tunnel_id is not None else ""
    if device_b is not None:
        return f"EoIP: {device_a.name} <-> {device_b.name}" + (f" ({label})" if label else "") + suffix
    return f"EoIP: {device_a.name}" + (f" ({label})" if label else "") + suffix


def _slugify(text: str) -> str:
    import re
    return re.sub(r'[^a-zA-Z0-9]+', '-', text).strip('-').lower()[:100]


def apply_confirmed(nb_api, confirmed, commit: bool):
    '''Reports (and, if commit, creates) one vpws L2VPN per confirmed
    two-sided tunnel pair, skipping either interface that's already
    terminated.'''
    created = 0
    for device_a, iface_a_name, device_b, iface_b_name, tunnel_id in confirmed:
        iface_a = resolve_interface(nb_api, device_a, iface_a_name)
        iface_b = resolve_interface(nb_api, device_b, iface_b_name)
        label = f"{device_a.name}/{iface_a_name} <-> {device_b.name}/{iface_b_name} (id={tunnel_id})"

        if iface_a is None or iface_b is None:
            print(f"SKIP (interface not found in NetBox)  {label}")
            continue
        if _already_terminated(nb_api, iface_a) or _already_terminated(nb_api, iface_b):
            print(f"SKIP (already synced)                 {label}")
            continue

        if not commit:
            print(f"WOULD CREATE                          {label}")
            continue

        try:
            name = _l2vpn_name(device_a, device_b, tunnel_id=tunnel_id)
            l2vpn = nb_api.vpn.l2vpns.create(
                name=name, slug=_slugify(name), type='vpws', identifier=tunnel_id,
            )
            nb_api.vpn.l2vpn_terminations.create(
                l2vpn=l2vpn.id, assigned_object_type='dcim.interface', assigned_object_id=iface_a.id,
            )
            nb_api.vpn.l2vpn_terminations.create(
                l2vpn=l2vpn.id, assigned_object_type='dcim.interface', assigned_object_id=iface_b.id,
            )
            print(f"CREATED                                {label}")
            created += 1
        except pynetbox.RequestError as exc:
            print(f"FAILED ({exc})                        {label}")

    return created


def apply_single_sided(nb_api, single_sided, commit: bool):
    '''Reports (and, if commit, creates) one vpws L2VPN per single-sided
    tunnel, with one termination (our own side only) and a description
    recording why the far side wasn't resolved.'''
    created = 0
    for device_a, iface_a_name, tunnel_id, remote_address, reason in single_sided:
        iface_a = resolve_interface(nb_api, device_a, iface_a_name)
        label = f"{device_a.name}/{iface_a_name} -> {remote_address} (id={tunnel_id}, {reason})"

        if iface_a is None:
            print(f"SKIP (interface not found in NetBox)  {label}")
            continue
        if _already_terminated(nb_api, iface_a):
            print(f"SKIP (already synced)                 {label}")
            continue

        if not commit:
            print(f"WOULD CREATE (single-sided, {reason:11s}) {label}")
            continue

        descriptions = {
            'unresolved': f"Remote address {remote_address} doesn't match any NetBox device/interface.",
            'out-of-scope': f"Remote address {remote_address} resolves to a NetBox device not collected "
                             "from this run (not RouterOS, unreachable, or out of --netbox-device scope).",
            'orphaned': f"Remote address {remote_address} resolves to a collected device with no "
                        "reciprocal EoIP tunnel -- likely stale config, worth a manual check.",
        }
        try:
            name = _l2vpn_name(device_a, label=str(remote_address), tunnel_id=tunnel_id)
            l2vpn = nb_api.vpn.l2vpns.create(
                name=name, slug=_slugify(name), type='vpws', identifier=tunnel_id,
                description=descriptions[reason],
            )
            nb_api.vpn.l2vpn_terminations.create(
                l2vpn=l2vpn.id, assigned_object_type='dcim.interface', assigned_object_id=iface_a.id,
            )
            print(f"CREATED (single-sided, {reason:11s})  {label}")
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

    orphaned = [s for s in single_sided if s[4] == 'orphaned']
    out_of_scope = [s for s in single_sided if s[4] == 'out-of-scope']
    unresolved = [s for s in single_sided if s[4] == 'unresolved']

    print(f"\n{len(confirmed)} confirmed (two-sided) tunnel(s), "
          f"{len(single_sided)} single-sided "
          f"({len(out_of_scope)} out-of-scope, {len(orphaned)} orphaned, "
          f"{len(unresolved)} unresolved).\n")

    if not args.commit:
        print("--- DRY RUN (pass --commit to actually create L2VPNs) ---")

    created = apply_confirmed(nb_api, confirmed, args.commit)
    created += apply_single_sided(nb_api, single_sided, args.commit)

    if args.commit:
        print(f"\nCreated {created} L2VPN(s).")


if __name__ == "__main__":
    main()
