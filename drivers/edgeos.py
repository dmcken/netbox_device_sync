'''
Driver for Ubiquiti EdgeOS devices (EdgeRouter)


Notes:
Easiest method seems to be fetch config via SCP /config/config.boot
Parse using vyatta-conf-parser (I already have a fork of it).

'''
# System import
import ipaddress
import logging
import pprint
import re
import typing

# External imports
import paramiko
import paramiko.client
import vyattaconfparser

# Local imports
import drivers.base

logger = logging.getLogger(__name__)

class EdgeOS(drivers.base.DriverBase):
    '''
    RouterOS device driver
    '''
    _connect_params = {
        'hostname': {'dest': 'host'},
        'username': {'dest': 'username'},
        'password': {'dest': 'password'},
        #'keyfile':  {'dest': 'ssh_private_key_file'},
    }

    _interfaces_to_ignore = [
        'dummy0',
        'itf',               # Seems to be linked to switch0 interface
        'itf0',
        'itf1',
        'itf2',
        'itf3',
        'imq0',
        'loop0',
        'loop1',
        'loop2',
        'loop3',
        'npi0',
        'npi1',
        'npi2',
        'npi3',
    ]
    _interfaces_to_ignore_regex = f"({'|'.join(_interfaces_to_ignore)})"

    def _connect(self, **kwargs) -> None:
        '''
        '''
        try:
            logger.debug(f"Attempting to connect to Ubnt EdgeOS device: {kwargs}")
            self._dev = paramiko.client.SSHClient()
            self._dev.load_system_host_keys()
            self._dev.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
            self._dev.connect(
                hostname=kwargs['host'],
                username=kwargs['username'],
                password=kwargs['password'],
                timeout=30,
            )
            self._dev.exec_command('terminal length 0')
        except paramiko.ssh_exception.AuthenticationException as exc:
            raise drivers.base.AuthenticationError from exc
        except paramiko.ssh_exception.SSHException as exc:
            raise drivers.base.ConnectError from exc

    def _close(self,):
        try:
            if self._dev:
                self._dev.close()
            del self._dev
        except AttributeError:
            pass

    def _fetch_show_interfaces(self) -> typing.List[str]:
        '''Fetch the output of 'show interfaces' with caching'''

        logger.debug("Entered EdgeOS._fetch_show_interfaces")
        if 'show-interfaces' not in self._cache:
            _, stdout, _ = self._dev.exec_command(
                '/opt/vyatta/bin/vyatta-op-cmd-wrapper show interfaces detail',
                timeout=30,
            )
            self._cache['show-interfaces'] = stdout.read().decode('utf-8')

        return self._cache['show-interfaces']

    def _fetch_show_configuration(self) -> typing.List[str]:
        '''Fetch the output of 'show configuration' with caching'''

        logger.debug("Entered EdgeOS._fetch_show_interfaces")
        if 'show-configuration' not in self._cache:
            _, stdout, _ = self._dev.exec_command(
                '/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration',
                timeout=30,
            )
            self._cache['show-configuration'] = stdout.read().decode('utf-8')

        return self._cache['show-configuration']

    def _parse_show_configuration(self):
        '''Parse the configuration.
        '''

        if 'parsed-config' not in self._cache:
            raw_config = self._fetch_show_configuration()
            conf_dict = vyattaconfparser.parse_conf(raw_config)
            self._cache['parsed-config'] = conf_dict

        return self._cache['parsed-config']

    def _determine_interface_type(self, interface_name: str) -> str:
        '''Return a type for
        '''

        type_map = {
            'eth': 'ethernet',
            'bond': 'bonding',
            'lo': 'loopback',
            'switch': 'switch',
            'npi': 'internal-ethernet',
            'imq': 'internal-offload',
            'br': 'switch',
            'itf': 'internal-ethernet',
            'tun': 'virtual',
        }

        res = re.match(r'([A-Za-z0-9]+)\.([0-9]+)', interface_name)
        if res: # We found a vlan ID
            return 'vlan'

        res = re.match(f"({'|'.join(type_map.keys())})", interface_name)
        if res:
            return type_map[res.group(1)]

        logger.error(f"Unable to determine type for interface {interface_name}")
        return None

    def _parse_show_interfaces(self):
        '''Parse the output of show interfaces to a dictionary of attributes, with caching.


        # An example entry from show interfaces will look like this.
        eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
            link/ether 24:a4:3c:3c:8f:b0 brd ff:ff:ff:ff:ff:ff
            inet 10.254.253.10/30 brd 10.254.253.11 scope global eth2
            valid_lft forever preferred_lft forever
            inet6 fe80::26a4:3cff:fe3c:8fb0/64 scope link
            valid_lft forever preferred_lft forever
            Description: DAN-CE2

            RX:  bytes    packets     errors    dropped    overrun      mcast
            657868058     624623          0         46          0      15692
            TX:  bytes    packets     errors    dropped    carrier collisions
            79837330     486854          0          0          0          0
        '''
        logger.debug("Entered EdgeOS._parse_show_interfaces")

        # These should be isolated
        re_full_interface_name = r'([A-Za-z0-9@\.]+)'
        re_interface_status_flags = r'([\w,-]+)'
        re_mtu = r'(\d+)'
        re_qdisc = r'(\w+)'
        re_interface_state = r'(\w+)'
        re_interface_group = r'(\w+)'
        re_qlen = r'(\d+)'
        re_mac = r'([A-Fa-f0-9:]+)'
        re_address_family = '(inet|inet6)'
        re_ip = r'([0-9A-Fa-f:\.]+)'
        rep_ip_with_mask = r'([0-9A-Fa-f:\.]+)/([0-9]+)'
        re_address_scope = r'(\w+)'
        re_interface_name = r'([A-Za-z0-9@\.]+)'

        self._fetch_show_interfaces()

        if 'show-interfaces-parsed' in self._cache:
            return self._cache['show-interfaces-parsed']

        interface_list = []
        curr_interface = {}
        position = 'root'
        # logger.debug(f"Show interfaces output:\n{self._cache['show-interfaces']}")

        for curr_line in self._cache['show-interfaces'].splitlines():
            # Check for a begining of status line
            res = re.match(
                f'{re_full_interface_name}: <{re_interface_status_flags}> mtu {re_mtu} qdisc {re_qdisc}( master {re_full_interface_name}|) state {re_interface_state} group {re_interface_group} qlen {re_qlen}',
                curr_line
            )
            if res:
                # We have hit a new interface, do we have a previous set of data?
                if curr_interface:
                    interface_list.append(curr_interface)
                    curr_interface = {}
                    position = 'root'

                # Set everything from the regex
                curr_interface['InterfaceStatusFlags'] = res.group(2).split(',')
                curr_interface['MTU'] = int(res.group(3))
                curr_interface['QDISC'] = res.group(4)
                curr_interface['LAG'] = res.group(6)
                curr_interface['InterfaceState'] = res.group(7)
                curr_interface['InterfaceGroup'] = res.group(8)
                curr_interface['QLEN'] = int(res.group(9))

                # Now lets clean the values
                curr_interface['FullInterfaceName'] = res.group(1)
                if curr_interface['FullInterfaceName'] in self._interfaces_to_ignore:
                    continue
                if curr_interface['FullInterfaceName'].find('@') != -1:
                    parts = curr_interface['FullInterfaceName'].split('@')
                    curr_interface['FullInterfaceName'] = parts[0]
                    curr_interface['Parent'] = parts[1]

                curr_interface['InterfaceType'] = self._determine_interface_type(curr_interface['FullInterfaceName'])

                if curr_interface['InterfaceType'] == 'vlan':
                    parts = curr_interface['FullInterfaceName'].rsplit('.', maxsplit=1)
                    curr_interface['Parent'] = parts[0]
                    curr_interface['Vlan'] = int(parts[1])

                try:
                    if curr_interface['Parent'] == 'NONE':
                        del curr_interface['Parent']
                except KeyError:
                    pass

                continue

            # These are the lines that require no special state
            res = re.match(r'\s+Description: (.*)', curr_line)
            if res:
                curr_interface['Description'] = res.group(1)
                continue

            res = re.match(f'\s+link/ether {re_mac} brd {re_mac}', curr_line)
            if res:
                curr_interface['MAC'] = res.group(1)
                curr_interface['Broadcast'] = res.group(2)
                continue

            # These lines require specific states
            if position == 'RX-stats':
                parts = curr_line.split()
                curr_interface['RX-bytes'] = int(parts[0])
                curr_interface['RX-packets'] = int(parts[1])
                curr_interface['RX-errors'] = int(parts[2])
                curr_interface['RX-dropped'] = int(parts[3])
                curr_interface['RX-overrun'] = int(parts[4])
                curr_interface['RX-mcast'] = int(parts[5])
                position = 'root'
                continue

            if position == 'TX-stats':
                parts = curr_line.split()
                curr_interface['TX-bytes'] = int(parts[0])
                curr_interface['TX-packets'] = int(parts[1])
                curr_interface['TX-errors'] = int(parts[2])
                curr_interface['TX-dropped'] = int(parts[3])
                curr_interface['TX-carrier'] = int(parts[4])
                curr_interface['TX-collisions'] = int(parts[5])
                position = 'root'
                continue

            if position == 'ipaddress':
                curr_interface['Addresses'][-1]['Flags'] = curr_line.split()
                position = 'root'
                continue

            # These lines set state
            res = re.match(
                f'\s+{re_address_family} {rep_ip_with_mask}( brd {re_ip}|) scope {re_address_scope}( {re_interface_name}|)',
                curr_line
            )
            if res:
                if 'Addresses' not in curr_interface:
                    curr_interface['Addresses'] = []

                address_rec = {
                    'AddressFamily': res.group(1),
                    'Address': ipaddress.ip_interface(f"{res.group(2)}/{res.group(3)}"),
                    'Scope': res.group(6),
                    'Interface': res.group(8),
                }
                if res.group(5):
                    address_rec['Broadcast'] = ipaddress.ip_address(res.group(5))
                else:
                    address_rec['Broadcast'] = None

                curr_interface['Addresses'].append(address_rec)
                position = 'ipaddress'
                continue

            res = re.match(
                r'\s+RX:\s+bytes\s+packets\s+errors\s+dropped\s+overrun\s+mcast',
                curr_line
            )
            if res:
                position = 'RX-stats'
                continue

            res = re.match(
                r'\s+TX:\s+bytes\s+packets\s+errors\s+dropped\s+carrier\s+collisions',
                curr_line
            )
            if res:
                position = 'TX-stats'
                continue

        # Cache data
        self._cache['show-interfaces-parsed'] = interface_list
        # for curr_interface in interface_list:
        #     if re.match(self._interfaces_to_ignore_regex, curr_interface['FullInterfaceName']):
        #         continue
        #     logger.debug(f"Interface data :\n{pprint.pformat(curr_interface, width=200)}")

        return self._cache['show-interfaces-parsed']

    def get_interfaces(self):
        '''

        We don't get the type from the 'show interfaces' so we will map the
        devices outselves.

        '''
        logger.debug("Entered EdgeOS.get_interfaces")
        raw_interfaces = self._parse_show_interfaces()
        config = self._parse_show_configuration()

        interfaces = []
        interface_map = {
            'bonding': 'lag',
            'loopback': 'virtual',
            'switch': 'bridge',
            'vlan': 'virtual',
        }

        switch_ports = {}
        if 'switch' in config['interfaces']:
            # We have a switch interface
            for curr_switch in config['interfaces']['switch'].keys():
                for curr_switch_port in config['interfaces']['switch'][curr_switch]['switch-port']['interface'].keys():
                    switch_ports[curr_switch_port] = curr_switch

        # logger.debug(f"Switch ports:\n{switch_ports}")

        for curr_int in raw_interfaces:

            try:
                if re.match(self._interfaces_to_ignore_regex, curr_int['FullInterfaceName']):
                    continue
            except KeyError:
                logger.error(f"Key error - interface {pprint.pformat(curr_int)}")
                raise

            interface_record = drivers.base.Interface(
                name=curr_int['FullInterfaceName'],
                mtu=curr_int['MTU'],
            )

            try:
                interface_record.type = interface_map[curr_int['InterfaceType']]
            except KeyError:
                interface_record.type = curr_int['InterfaceType']

            if interface_record.type == 'ethernet':
                # This causes the type to be left alone.
                interface_record.type = None

            try:
                # For specific values of MAC leave it as None
                if curr_int['MAC'].strip() not in ['']:
                    interface_record.mac_address = curr_int['MAC'].strip()
            except KeyError:
                # The MAC is not set on EdgeOS devices loopback
                if curr_int['FullInterfaceName'] not in ['lo','tun0',]:
                    logger.error(f"MAC not set on interface: {curr_int['FullInterfaceName']}")
                interface_record.mac_address = ''

            try:
                interface_record.description = curr_int['Description']
            except KeyError:
                interface_record.description = ''

            if 'LAG' in curr_int and curr_int['LAG']:
                interface_record.lag = curr_int['LAG']

            if 'Parent' in curr_int and curr_int['Parent']:
                if not re.match(self._interfaces_to_ignore_regex, curr_int['Parent']):
                    interface_record.parent = curr_int['Parent']

            if interface_record.name in switch_ports:
                interface_record.bridge = switch_ports[interface_record.name]

            interfaces.append(interface_record)
            # logger.debug(f"Interface: {interface_record}")

        return interfaces


    def get_ipaddresses(self):
        '''Get IP addresses assigned to device.
        '''
        logger.debug("Entered EdgeOS.get_ipaddresses")

        raw_interfaces = self._parse_show_interfaces()

        address_list = []
        for curr_int in raw_interfaces:
            if re.match(self._interfaces_to_ignore_regex, curr_int['FullInterfaceName']):
                continue

            if 'Addresses' not in curr_int:
                continue

            for curr_address in curr_int['Addresses']:

                if curr_address['Address'] in self._addresses_to_ignore:
                    continue

                address_rec = drivers.base.IPAddress(
                    address=curr_address['Address'],
                    interface=curr_int['FullInterfaceName'],
                    status='active',
                    vrf=None,
                )
                address_list.append(address_rec)
                # logger.debug(f"Addresses: {address_rec}")

        return address_list
