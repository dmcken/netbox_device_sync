'''Mikrotik routeros driver'''

# System import
import ipaddress
import logging
import pprint
import socket

# External import
import librouteros

# Local import
import drivers.base

logger = logging.getLogger(__name__)

class RouterOS(drivers.base.DriverBase):
    '''RouterOS device driver'''

    _connect_params = {
        'hostname': {'dest': 'host'},
        'username': {'dest': 'username'},
        'password': {'dest': 'password'},
        #'keyfile':  {'dest': 'ssh_private_key_file'},
    }

    _type_map = {
        'bond':   'lag',
        'bridge': 'bridge',
        'eoip':   'virtual',
        'ether':  None,        # Most will already be defined by the templates
        'vlan':   'virtual',
        'vrrp':   'virtual',
    }
    _parent_types = [
        'lag',
        'bridge',
    ]

    def _connect(self, **kwargs) -> None:
        """Connect to device.

        Raises:
            drivers.base.AuthenticationError: _description_
            drivers.base.ConnectError: _description_
        """
        try:
            # Connection type, 6.43 and later use plain, before that uses token
            # https://librouteros.readthedocs.io/en/3.2.0/connect.html
            # kwargs['login_method'] = librouteros.login.plain
            logger.debug(f"Attempting to connect to RouterOS device: {kwargs}")
            self._dev = librouteros.connect(**kwargs)
        except librouteros.exceptions.TrapError as exc:
            # TODO: Check for specific message 'invalid user name or password (6)'
            raise drivers.base.AuthenticationError() from exc
        except socket.timeout as exc:
            raise drivers.base.ConnectError() from exc

    def _close(self,) -> None:
        """Close connection to device.
        """
        try:
            if self._dev:
                self._dev.close()
            del self._dev
        except AttributeError:
            pass

    def get_interfaces(self,) -> None:
        '''Get interfaces associated with device'''

        rez_parent_interfaces = []
        rez_interfaces = []

        # 1-to-1 mappings
        bridge_ports = list(self._dev.path('interface','bridge','port'))
        bridge_ports_slave_dict = {v['interface']:v for v in bridge_ports}

        vlan_ints = list(self._dev.path('interface','vlan'))
        vlan_ints_parent_dict = {v['name']:v for v in vlan_ints}

        vrrp_ints = list(self._dev.path('interface','vrrp'))
        vrrp_ints_slave_dict = {v['name']:v for v in vrrp_ints}

        # 1-to-many mappings
        lag_ints = list(self._dev.path('interface','bonding'))
        lag_ints_slave_dict = {}
        for curr_lag in lag_ints:
            for curr_slave in curr_lag['slaves'].split(','):
                lag_ints_slave_dict[curr_slave] = curr_lag


        ros_interfaces = list(self._dev.path('interface'))

        for curr_interface in ros_interfaces:
            logger.debug(f"Interface data: {pprint.pformat(curr_interface)}")

            interface_rec = drivers.base.Interface(
                name=curr_interface['name'],
                mac_address=[],
            )

            try:
                # For specific values of MAC ignore them
                if interface_rec.mac_address not in ['','00:00:00:00:00:00']:
                    interface_rec.mac_address.append(
                        curr_interface['mac-address']
                    )
            except KeyError:
                pass

            try:
                interface_rec.mtu = int(curr_interface['mtu'])
            except ValueError:
                try:
                    interface_rec.mtu = int(curr_interface['actual-mtu'])
                except KeyError:
                    interface_rec.mtu = None
            except KeyError:
                logger.error(f"Missing MTU for interface: {curr_interface['name']}")
                interface_rec.mtu = None

                # logger.error("Invalid MTU '{0}' on {1}".format(
                #     curr_interface['mtu'],
                #     curr_interface,
                # ))

            try:
                interface_rec.description = curr_interface['comment'].strip()
            except KeyError:
                interface_rec.description = None

            # Map from mikrotik types to netbox types
            try:
                interface_rec.type = self._type_map[curr_interface['type']]
            except KeyError:
                interface_rec.type = None

            # Make sure we have the parents created first.
            if interface_rec.type in self._parent_types:
                rez_parent_interfaces.append(interface_rec)
            else:
                # Handle the parent relationships
                if interface_rec.name in bridge_ports_slave_dict:
                    interface_rec.bridge = bridge_ports_slave_dict[
                        interface_rec.name
                    ]['bridge']

                if interface_rec.name in lag_ints_slave_dict:
                    interface_rec.lag = lag_ints_slave_dict[
                        interface_rec.name
                    ]['name']

                if interface_rec.name in vlan_ints_parent_dict:
                    interface_rec.parent = vlan_ints_parent_dict[
                        interface_rec.name
                    ]['interface']

                if interface_rec.name in vrrp_ints_slave_dict:
                    interface_rec.parent = vrrp_ints_slave_dict[
                        interface_rec.name
                    ]['interface']

                rez_interfaces.append(interface_rec)

        return rez_parent_interfaces + rez_interfaces

    def get_ipaddresses(self):

        rez_ip_addresses = []

        families = {
            4: self._dev.path('ip','address'),
            6: self._dev.path('ipv6','address'),
        }
        for family,data in families.items():

            ros_ips = list(data)

            for curr_ip_addr in ros_ips:
                logger.debug(f"IPv{family} address: {curr_ip_addr}")
                try:
                    if curr_ip_addr['link-local'] is True:
                        continue
                except KeyError:
                    pass

                # Using depreciated for disabled IPs
                ip_status = 'active'
                if curr_ip_addr['disabled'] is True:
                    ip_status = 'deprecated'

                ip_rec = drivers.base.IPAddress(
                    address = ipaddress.ip_interface(curr_ip_addr['address']),
                    interface = curr_ip_addr['interface'],
                    status = ip_status,
                    vrf = None,
                )

                rez_ip_addresses.append(ip_rec)

        return rez_ip_addresses

    def get_neighbours(self,) -> list[drivers.base.Neighbour]:
        """Get neighbours to a device.

        Returns:
            list[Neighbour]: List of neighbours to this device.
        """
        res_neighbours = []


        to_check = {
            'ARP':   {
                'path': self._dev.path('ip','arp'),
                'map': {
                    'mac': 'mac-address',
                    'ip': 'address',
                    'interface': 'interface',
                },
                'filter': lambda x: x['complete'] == True,
            },
            # 'DHCP4': {
            #     'path': self._dev.path('ip','dhcp-server','lease'),
            #     'dhcp-server-path': self._dev.path('ip','dhcp-server'),
            #     'map': {
            #         'mac': 'mac-address',
            #         'ip': 'address',
            #         'interface': 'interface',
            #     }
            # },
            # 'LLDP':  {
            #     'path': self._dev.path('ip','neighbor'),
            #     'map': {
            #         'mac': 'mac-address',
            #         'ip': 'address',
            #         'interface': 'interface',
            #         'name': 'identity',
            #     },
            # },
            #'NDP':   {'path': self._dev.path('ipv6','neighbour') },
            #'DHCP6': {'path': self._dev.path('ipv6','dhcp-server','binding') },
        }
        for source, data in to_check.items():
            entries = list(data['path'])
            if 'filter' in data:
                entries = filter(data['filter'], entries)

            # if 'dhcp-server-path' in data:


            for curr_entry in entries:
                entry_data = {'source': source}
                for dst,src in data['map'].items():
                    if dst == 'mac':
                        # MACs is now a list
                        entry_data[dst] = [curr_entry[src]]
                    else:
                        entry_data[dst] = curr_entry[src]

                neighbour_rec = drivers.base.Neighbour(**entry_data)
                res_neighbours.append(neighbour_rec)

        return res_neighbours
