#!/usr/bin/python3
'''Push Mikrotik RouterOS IP pool (/ip/pool) usage into Zabbix.

RouterOS doesn't expose pool usage over SNMP, so this connects to each
RouterOS device directly (same driver/credentials as the rest of this
repo), reads its pools' total/used/free counts, and pushes them to
Zabbix as trapper items via the Zabbix sender protocol - feeding the
'AL - Mikrotik IP Pools' template's LLD discovery rule
(mikrotik.pool.discovery) and item prototypes
(mikrotik.pool.{total,used,free,free_pct}[{#POOLNAME}]), which has a
trigger prototype firing when a pool drops below 10% free.

Meant to run on a schedule (cron), same as the rest of this repo's
sync scripts.
'''

# System imports
import argparse
import json
import logging
import os
import re
import socket
import struct

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

DEFAULT_SENDER_HOST = '172.16.17.120'
DEFAULT_SENDER_PORT = 10051

# Mirrors NetworkDevice._clean_hostname in netbox-zabbix-sync's
# netbox_zabbix_sync.py - that's what turns a Netbox device name into
# its Zabbix host's 'host' field, and sender data has to target that
# exact name. Kept as a literal copy rather than a cross-repo import so
# this script has no dependency on the other repo; a real device name
# containing none of this regex's disallowed characters (true for every
# RouterOS device seen so far) makes this a no-op anyway.
_HOST_DISALLOWED_CHARS = re.compile(r'[^A-Za-z0-9 ._-]')


def zabbix_host_name(device_name: str) -> str:
    '''Netbox device name -> the Zabbix host name it was synced under.'''
    return _HOST_DISALLOWED_CHARS.sub('_', device_name)


def send_to_zabbix(sender_host: str, sender_port: int, items: list) -> dict:
    '''Sends a batch of (host, key, value) trapper values to Zabbix over
    the sender protocol (ZBXD\\x01 + 8-byte length + 8-byte reserved +
    JSON). Returns the server's parsed JSON response.
    '''
    payload = json.dumps({
        'request': 'sender data',
        'data': [{'host': h, 'key': k, 'value': v} for h, k, v in items],
    }).encode('utf-8')
    header = b'ZBXD\x01' + struct.pack('<Q', len(payload)) + struct.pack('<Q', 0)

    with socket.create_connection((sender_host, sender_port), timeout=10) as sock:
        sock.sendall(header + payload)
        resp_header = sock.recv(13)
        if resp_header[:5] != b'ZBXD\x01':
            raise RuntimeError(f"Unexpected Zabbix sender response header: {resp_header!r}")
        resp_len = struct.unpack('<Q', resp_header[5:13])[0]
        resp_body = b''
        while len(resp_body) < resp_len:
            chunk = sock.recv(resp_len - len(resp_body))
            if not chunk:
                break
            resp_body += chunk

    return json.loads(resp_body.decode('utf-8'))


def collect_pool_items(nb_api, device_credentials, device_filter) -> list:
    '''Connects to every eligible RouterOS device and builds the full
    sender batch: one discovery (LLD) value per device, plus four value
    items per pool. A device that can't be reached is logged and
    skipped, same as this repo's other sync scripts - one unreachable
    router doesn't stop the run.
    '''
    items = []
    for device_nb in nb_api.dcim.devices.all():
        if device_nb.role.slug in utils.device_roles_to_ignore:
            continue
        if str(device_nb.platform) != 'RouterOS':
            continue
        if device_nb.primary_ip is None:
            continue
        if device_nb.status.value not in utils.acceptable_device_status:
            continue
        if device_filter and device_nb.name not in device_filter:
            continue

        device_ip = str(device_nb.primary_ip).split('/', maxsplit=1)[0]
        try:
            full_dev_creds = {**device_credentials, 'hostname': device_ip}
            device_conn = drivers.routeros.RouterOS(**full_dev_creds)
            pools = device_conn.get_ip_pools()
            del device_conn
        except drivers.base.ConnectError as exc:
            logger.warning(f"Could not connect to {device_nb.name} ({device_ip}): {exc}")
            continue
        # pylint: disable=broad-except
        except Exception as exc:
            logger.warning(f"Error collecting pools from {device_nb.name}: {exc.__class__.__name__}: {exc}")
            continue

        host = zabbix_host_name(device_nb.name)
        discovery = {'data': [{'{#POOLNAME}': p.name} for p in pools]}
        items.append((host, 'mikrotik.pool.discovery', json.dumps(discovery)))

        for p in pools:
            total = p.total or 0
            used = p.used or 0
            free = p.available if p.available is not None else max(total - used, 0)
            free_pct = (free / total * 100) if total else 0.0
            items.append((host, f'mikrotik.pool.total[{p.name}]', str(total)))
            items.append((host, f'mikrotik.pool.used[{p.name}]', str(used)))
            items.append((host, f'mikrotik.pool.free[{p.name}]', str(free)))
            items.append((host, f'mikrotik.pool.free_pct[{p.name}]', f'{free_pct:.2f}'))

        logger.info(f"{device_nb.name}: {len(pools)} pool(s) collected.")

    return items


def parse_arguments() -> argparse.Namespace:
    '''Parse CLI arguments.'''
    parser = argparse.ArgumentParser(
        prog="IP pool sync",
        description=__doc__,
    )
    parser.add_argument(
        '-n', '--netbox-device', nargs='+', default=[],
        help="Only collect from these Netbox devices.",
    )
    parser.add_argument('--sender-host', default=DEFAULT_SENDER_HOST)
    parser.add_argument('--sender-port', type=int, default=DEFAULT_SENDER_PORT)
    parser.add_argument('-d', '--debug', action='store_true', help="Verbose logging.")
    return parser.parse_args()


def main():
    '''Entry point.'''
    args = parse_arguments()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format=LOGGING_FORMAT,
    )
    logging.getLogger('librouteros').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)

    nb_api = pynetbox.api(
        os.environ.get('NB_URL'),
        token=os.environ.get('NB_TOKEN'),
        threading=True,
    )
    device_credentials = utils.parse_device_parameters()

    items = collect_pool_items(nb_api, device_credentials, args.netbox_device)
    if not items:
        logger.warning("No pool data collected from any device; nothing sent.")
        return

    response = send_to_zabbix(args.sender_host, args.sender_port, items)
    logger.info(f"Zabbix sender response: {response}")


if __name__ == "__main__":
    main()
