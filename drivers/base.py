'''Base classes for all device drivers.

Requirements for a driver:
- Modules                      => get_modules
    - Includes SFPs
- Vlans                        => get_vlans
    - Purely bridged vlans entities, vlan interfaces are handled by interfaces
- Interfaces                   => get_interfaces
    - VLAN
    - Parent interfaces
    -
- IP Addresses (IPv4 and IPv6) => get_ipaddresses
- Neighbours                   => get_neighbours

'''
# System imports
import abc
import dataclasses
import ipaddress
import logging

# Local imports
import utils

# Globals
logger = logging.getLogger(__name__)

# Exceptions
class ConnectError(Exception):
    '''General error if we can't connect'''

class AuthenticationError(Exception):
    '''Thrown if auhentiction to a device fails'''

# Data classes
@dataclasses.dataclass()
class Interface:
    """A network device interface"""
    name: str
    bridge: str | None = None
    description: str = None
    lag: str | None = None
    mac_address: str = None
    mtu: int | None = None
    parent: str | None = None
    type: str = None

@dataclasses.dataclass
class IPAddress:
    """IP Address"""
    address: ipaddress.IPv4Interface | ipaddress.IPv6Interface
    interface: str = None
    status: str = None
    vrf: str = None

@dataclasses.dataclass
class Route:
    '''Route definitions (most commonly static)'''
    prefix: ipaddress.IPv4Network | ipaddress.IPv6Network
    gateway: ipaddress.IPv4Address | ipaddress.IPv6Address

@dataclasses.dataclass
class Vlan:
    '''Vlan definition.

    These are vlans defined for the purposes of trunking.
    Vlan virtual interfaces (usually with IPs) are treated as interfaces.
    '''
    id: int
    bridge: str = None
    name: str = None
    description: str = None
    status: str = None

@dataclasses.dataclass
class Neighbour:
    '''Neighbour to current device.

    Can be lldp, CDP, ARP, NDP, etc.
    '''
    mac: str = None
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address = None
    name: str = None
    interface: str = None
    source: str = None
    extra_data: str = None

# Factories
class DriverFactory:
    """Base factory for all driver objects"""


class DriverBase(metaclass = abc.ABCMeta):
    '''

    Protocols:
    - If a value is unknown return None, the sync will ignore that value
      failing if it is required by netbox.

    To define in _connect_params:
    - hostname
    - username
    - password
    - key_file
    '''
    _addresses_to_ignore = utils.networks_to_ignore
    _link_local_subnet   = utils.link_local_subnet
    _connect_params = {}
    _connection = None
    # Regexes expected to be common to all drivers
    _common_re = {
        # MAC addresses
        'MAC': r'([A-Fa-f0-9:]+)',
        # IP addresses (v4 and v6)
        'IP':  r'([0-9A-Fa-f:\.]+)',
        'IP_WITH_MASK': r'([0-9A-Fa-f:\.]+)/([0-9]+)',
    }
    # To be overridden by the driver
    _dev_re = {}

    def __init__(self, **kwargs) -> None:

        # This cache is for storing data in the drivers between calls
        self._cache = {}

        # Parse the device connection parameters
        creds = {}
        for k,v in self._connect_params.items():
            try:
                creds[v['dest']] = kwargs[k]
            except KeyError:
                continue

        logger.debug(f"Creds within base: {creds}")

        self._connect(**creds)

    def __del__(self):
        self._close()

    @abc.abstractmethod
    def _connect(self, **kwargs):
        '''Creates a connection to the device.

        The incoming parameters will be from the config.py DEV_* with the DEV_
        prefix removed and then lowercased (e.g. DEV_USERNAME becomes username).
        The hostname parameter is also added to this set of parameters and is
        the current device's hostname / IP.

        These parameters are then filtered and mapped using the _connect_params:

        Example:
        _connect_params = {
            'hostname': 'host',
            'username': 'user',
            'keyfile':  'ssh_private_key_file',
        }

        will only accept the hostname, username, password and keyfile
        parameters and map them to host, user and ssh_private_key_file
        respectively.

        This setup should make allowing the drivers to share parameters that make
        sense and break out the ones that don't. An example of this could be
        defining DEV_ROUTEROS_PORT with a matching mapping of:
            'routeros_port': 'port',
        in the dictionary. The routeros driver will know what port to use for its
        connections without requiring any changes to the other drivers.
        '''

    @abc.abstractmethod
    def _close(self,):
        """Close the connection to the device.
        """

    @abc.abstractmethod
    def get_interfaces(self,) -> list[Interface]:
        '''Get interfaces associated with device.
        TODO: Document what is expected of the drivers

        Return:
        List of interface definitions:

        Interface definitions:
        - Dictionary containing the following fields:
        -- description: Description of the interface (string,mandatory)
        -- mac_address: MAC address of the interface (string,None allowed)
        -- mtu: MTU of the interface (integer,None allowed)
        -- name: Interface name (string,mandatory)
        -- type: Type of the interface (string,None allowed)

        Example:
        drivers.base.Interfaces(
            description=None,
            mac_address='64:87:88:ef:34:00',
            mtu=1514,
            name='ge-0/0/0',
            type=None
        )

        # The return ordering is important
        # We are creating certain parent interfaces like aeX, lo0 first
        # Then the physical interfaces (mostly confirming they are in place)
        # Finally the units built on top of the first two.
        '''

    @abc.abstractmethod
    def get_ipaddresses(self,):
        '''Get IP addresses assigned to device.
        TODO: Document what is expected of the drivers

        Return:
        list of IP definitions:

        IP definition:
        - Dictionary containing the following fields:
        -- address: IP With subnet mask (IPv4Interface or IPv6Interface, mandatory)
        -- interface:  name of the interface. (string,mandatory)
        -- status: One of the netbox IP address statuses.
           Current list: active,reserved,deprecated,dhcp,slaac (string,mandatory)
        -- vrf: VRF this IP sits within (string,If unknown set to None)
        Example:
        {
            'address': IPv4Interface('172.17.10.89/29'),
            'interface': 'ge-0/0/2.0',
            'status': 'active',
            'vrf': None
        }
        '''

    # @abc.abstractmethod
    def get_vlans(self,) -> list[Vlan]:
        """Get vlans configured on a device.

        Return a blank list if the driver doesn't implement.

        Returns:
            list[Vlan]: _description_
        """
        return []

    # @abc.abstractmethod
    def get_neighbours(self,) -> list[Neighbour]:
        """Get neighbours to a device.

        Return a blank list if the driver doesn't implement this function.

        Returns:
            list[Neighbour]: _description_
        """
        return []
