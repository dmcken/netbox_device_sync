'''
General Utility definitions and functions
'''


# System imports
import ipaddress
import os
import re

# Common definitions
link_local_subnet = ipaddress.ip_network('fe80::/10')

device_roles_to_ignore = [
    'dh-txrx-receivers',
    'generic',
    'patch-panel',
    'pdu',
    'svr-transcoder',
    'video-encoder',
    'video-satellite-receiver',
    'video-satellite-splitter',
]
networks_to_ignore = [
    # Pull full definitions from:
    # ipaddress._IPv4Constants
    # ipaddress._IPv6Constants
    ipaddress.ip_network('127.0.0.0/8'), # IPv4 Loopback
    ipaddress.ip_network('::1/128'),     # IPv6 Loopback
    ipaddress.ip_network('FE80::/10'),   # Link local
    # Shared local-management convenience address seen identically
    # configured on multiple independent AirFiber units' secondary
    # bridge (br2) - not a real per-device address, so not something
    # NetBox's global IP uniqueness should ever be asked to track.
    ipaddress.ip_network('192.168.2.0/24'),
]
acceptable_device_status = [
    'active',
]

# Utility functions
def parse_device_parameters():
    """Parse device connection parameters out of the environment (.env).

    Any DEV_* environment variable is picked up, with the DEV_ prefix
    stripped and the remainder lowercased as the resulting key.

    Returns:
        dict[str,str]: Device connection parameters.
    """
    device_credentials = {}
    for env_key, env_value in os.environ.items():
        attr_re = re.match("DEV_([A-Za-z0-9_]+)", env_key)
        if not attr_re:
            continue

        if not env_value:
            continue

        device_credentials[attr_re.group(1).lower()] = env_value

    return device_credentials

def clean_mac(mac_address: str) -> str:
    """Clean a MAC address.

    Netbox operates with upper-case mac addresses.

    Args:
        mac_address (str): _description_

    Returns:
        str: _description_
    """
    return mac_address.upper()

# Has to be defined down here so it can reference the utility functions.
interface_fields_to_sync = {
    'bridge': {},
    'description': {},
    'lag': {},
    'mac_address': {},
    'mtu': {},
    'name': {},
    'parent': {},
    'type': {},
}

macs_to_ignore = [
    None,
    '00:00:00:00:00:00',
]
