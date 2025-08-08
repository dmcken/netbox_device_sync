'''Juniper JunOS driver'''
import collections
import ipaddress
import jnpr.junos
import jnpr.junos.exception
import logging
import pprint
import re
import xmltodict
from lxml import etree

# Local imports
import drivers.base

logger = logging.getLogger(__name__)

class JunOS(drivers.base.DriverBase):
    '''Juniper JunOS driver'''

    _connect_params = {
        'hostname': {'dest': 'host'},
        'username': {'dest': 'user'},
        'password': {'dest': 'passwd'},
        'keyfile':  {'dest': 'ssh_private_key_file'},
    }
    _config = {
        'interfaces': {
            'filter': '<configuration><interfaces/></configuration>',
            'result': None,
        },
        'protocols': {
            'filter': '<configuration><protocols/></configuration>',
            'result': None,
        },
    }

    # Interfaces and logical units that are to be ignored
    # For Juniper naming conventions:
    # https://www.juniper.net/documentation/us/en/software/junos/interfaces-ethernet-switches/topics/topic-map/switches-interface-understanding.html
    # https://www.juniper.net/documentation/us/en/software/junos/interfaces-fundamentals/topics/topic-map/router-interfaces-overview.html
    # https://www.juniper.net/documentation/us/en/software/junos/interfaces-encryption/topics/topic-map/tunnel-services-overview.html
    _interfaces_to_ignore = [
        'ae[0-9]+.32767',               # We only want to ignore the .32767 sub-interface for any aeX interfaces
        'bme0',
        'cbp0',                         # Customer backbone port
        'dsc',                          # Discard interface
        'em[0-9]+',                          # Internal cross connect between routing engine and control board.
        'esi',                          # Ethernet segment identifier?
        'fxp2',     # Temp
        'fxp2.0',   # Temp
        'gre',                          # GRE
        'ipip',                         # IP-in-IP
        'jsrv',                         # Juniper services interface.
        'lc-[0-9]+/[0-9]+/[0-9]+',      # Internally generated interface that is not configurable.
        'lo0.16384',                    #
        'lo0.16385',                    #
        'lsi',                          #
        'lsq-0/0/0',                    # link services queuing interface
        'lt-0/0/0',                     #
        'mt-0/0/0',                     # Unknown
        'mtun',                         #
        'pfe-[0-9]+/[0-9]+/[0-9]+',     # Packet forwarding engine
        'pfh-[0-9]+/[0-9]+/[0-9]+',     # https://kb.juniper.net/InfoCenter/index?page=content&id=KB23578&cat=MX_SERIES&actp=LIST
        'pimd',                         #
        'pime',                         #
        'pp0',                          #
        'ppd0',                         #
        'ppe0',                         #
        'si-0/0/0.0',                   # Services-inline interface (only ignore the logical interfaces)
        'sp-0/0/0',                     #
        'sp-0/0/0.(0|16383)',           #
        'st0',                          #
        'tap',                          #
    ]
    _interfaces_to_ignore_regex = f'({"|".join(_interfaces_to_ignore)})'


    def _connect(self, **kwargs):
        '''
        '''
        try:
            logger.debug("Attempting to connect to JunOS device: {0}".format(kwargs))

            kwargs['gather_facts'] = True

            self._dev = jnpr.junos.Device(**kwargs)
            self._dev.open(normalize=True)
        except jnpr.junos.exception.ConnectError as e:
            raise drivers.base.ConnectError() from e
        except Exception as e:
            logger.error("General connection error: {0}".format(e))
            raise e from e

    def _close(self,):
        if self._dev:
            self._dev.close()
        del self._dev


    def _get_config(self, xml_filter=None):

        args = {
            'options': {
                # We always want the live config.
                'database' : 'committed'
            },
        }

        if xml_filter:
            args['xml_filter'] = xml_filter

        return self._dev.rpc.get_config(**args)


    def get_interfaces(self,):
        '''



        '''
        # TODO: Simplify and split up
        # TODO: lag slaves are not setup atm

        # Return objects
        parent_interfaces = []
        normal_interfaces = []
        interface_units = []

        active_interfaces = []
        rez = self._dev.rpc.get_interface_information()
        int_dict = xmltodict.parse(etree.tostring(rez))
        for curr_int in int_dict['interface-information']['physical-interface']:
            # Interfaces to ignore.
            if re.match(self._interfaces_to_ignore_regex, curr_int['name']):
                continue

            #logger.debug("Processing interface:\n{0}".format(pprint.pformat(curr_int, width=200)))
            interface_dict = drivers.base.Interface(
                name=f"{curr_int['name']}",
                mac_address=[],
            )

            try:
                interface_dict.description = curr_int['description']
            except KeyError:
                interface_dict.description = None

            try:
                if isinstance(curr_int['current-physical-address'], dict):
                    # Extract the mac from the dict object that likely looks like:
                    # {'#text': '54:e0:32:6b:e1:10','@format': 'MAC 54:e0:32:6b:e1:10'}
                    interface_dict.mac_address.append(curr_int['current-physical-address']['#text'])
                elif isinstance(curr_int['current-physical-address'], str):
                    # Sometimes it just the raw string.
                    interface_dict.mac_address.append(curr_int['current-physical-address'])
                else:
                    logger.error(f"Unknown MAC on interface: {pprint.pformat(curr_int)}")
            except KeyError:
                pass

            try:
                interface_dict.mtu = int(curr_int['mtu'])
            except ValueError:
                interface_dict.mtu = None
            except KeyError:
                logger.error(f"Missing MTU for interface: {curr_int}")
                interface_dict.mtu = None

            # Lag interfaces interfaces
            if re.match('ae[0-9]+', curr_int['name']):
                interface_dict.type = 'lag'
                parent_interfaces.append(interface_dict)
            #TODO: Handle bridge interfaces
            else: # Every other type of interface
                interface_dict.type = None
                normal_interfaces.append(interface_dict)

            # Now to handle all logical instances (units in JunOS parlance).
            if 'logical-interface' in curr_int:

                # In the case of a single unit it is a direct OrderedDict vs list of OrderedDict
                if isinstance(curr_int['logical-interface'], list):
                    logical_int_list = curr_int['logical-interface']
                else:
                    logical_int_list = [curr_int['logical-interface']]

                for curr_logical_int in logical_int_list:

                    if re.match(self._interfaces_to_ignore_regex, curr_logical_int['name']):
                        continue

                    try:
                        # aenet is the sub-interfaces on the slave interfaces for an aeX interface
                        # e.g. xe-0/0/0.5 is created automatically for ae0.5 if xe-0/0/0 is a
                        # slave of ae0.
                        if curr_logical_int['address-family']['address-family-name'] in ['aenet']:
                            '''
                            So via the 'show interfaces' output (be it terse, extensive, etc) there is
                            no output that explicitly lists the lag parent interface that we wish
                            to map in netbox.

                            e.g. data from curr_logical_int['address-family']['address-family-name']
                            OrderedDict([('address-family-name', 'aenet'), ('ae-bundle-name', 'ae0.0')])

                            e.g. output of 'show interfaces terse'
                            xe-1/2/2                up    up
                            xe-1/2/2.1              up    up   aenet    --> ae6.1

                            So we will have to look at the sub-interfaces
                            '''
                            #logger.error("LAG sub-interface: {0}".format(curr_logical_int['address-family']))
                            primary_lag_int,_ = curr_logical_int['address-family']['ae-bundle-name'].rsplit('.',maxsplit=1)
                            interface_dict.lag = primary_lag_int
                            continue
                    except (KeyError,TypeError):
                        pass

                    #logger.debug("Logical interface: {0}".format(pprint.pformat(curr_logical_int)))
                    try:
                        unit_descripion = curr_logical_int['description']
                    except KeyError:
                        unit_descripion = None

                    try:
                        unit_mtu = 0
                        if isinstance(curr_logical_int['address-family'], list):
                            address_family_list = curr_logical_int['address-family']
                        else:
                            address_family_list = [curr_logical_int['address-family']]
                    except KeyError:
                        # No address families under the unit, why?
                        # Log and handle errors
                        continue

                    for curr_address_family in address_family_list:

                        try:
                            address_family_mtu = int(curr_address_family['mtu'])
                        except (ValueError, KeyError):
                            address_family_mtu = 0

                        if address_family_mtu > unit_mtu:
                            unit_mtu = address_family_mtu

                    # Seems for the ethernet-switching family the MTU returned is 0
                    if unit_mtu == 0:
                        unit_mtu = interface_dict.mtu

                    interface_units.append(drivers.base.Interface(
                        name=f"{curr_logical_int['name']}",
                        mtu=unit_mtu,
                        mac_address=[],
                        type='virtual',
                        description=unit_descripion,
                        parent=f"{curr_int['name']}",
                    ))

        int_filter = '<configuration><interfaces/><protocols/></configuration>'
        dev_config = self._dev.rpc.get_config(
            filter_xml=int_filter,
            options={'database' : 'committed'}
        )
        config_dict = xmltodict.parse(etree.tostring(dev_config))

        # From the config we can fetch the layer 2 info (lags and vlan config)

        # This ordering is important
        # We are creating certain parent interfaces like aeX, lo0 first
        # Then the physical interfaces (mostly confirming they are in place)
        # Finally the units built on top of the first two.
        return parent_interfaces + normal_interfaces + interface_units

    def get_ipaddresses(self,):
        '''
        '''

        ip_addresses = []

        rez = self._dev.rpc.get_interface_information()
        int_dict = xmltodict.parse(etree.tostring(rez))
        for curr_int in int_dict['interface-information']['physical-interface']:

            # Skip the ignored interfaces
            if re.match(self._interfaces_to_ignore_regex, curr_int['name']):
                continue

            #logger.info("Processing interface: {0}".format(curr_int['name']))
            if 'logical-interface' in curr_int:
                # In the case of a single unit it is a direct OrderedDict vs list of OrderedDict
                if isinstance(curr_int['logical-interface'], list):
                    logical_int_list = curr_int['logical-interface']
                else:
                    logical_int_list = [curr_int['logical-interface']]

                for curr_logical_int in logical_int_list:

                    if curr_logical_int['name'] in self._interfaces_to_ignore:
                        continue

                    #logger.debug("Logical interface:\n{0}\n{1} - {2}".format(pprint.pformat(curr_logical_int),
                    #    curr_logical_int['name'], curr_logical_int['name'] in self._interfaces_to_ignore))

                    try:
                        unit_mtu = 0
                        if isinstance(curr_logical_int['address-family'], list):
                            address_family_list = curr_logical_int['address-family']
                        else:
                            address_family_list = [curr_logical_int['address-family']]
                    except KeyError:
                        # No address families under the unit, why?
                        continue

                    for curr_address_family in address_family_list:
                        if curr_address_family['address-family-name'] not in ['inet', 'inet6']:
                            continue


                        #logger.debug("curr_address_family on: {0}\n{1}".format(curr_logical_int['name'],pprint.pformat(curr_address_family)))

                        try:
                            if isinstance(curr_address_family['interface-address'], list):
                                interface_address_list = curr_address_family['interface-address']
                            else:
                                interface_address_list = [curr_address_family['interface-address']]
                        except KeyError:
                            # To handle cases like this:
                            # unit 0 {
                            #     family inet;
                            # }
                            continue

                        for curr_address in interface_address_list:
                            try:
                                _,subnet = curr_address['ifa-destination'].split('/')

                                interface_addr = ipaddress.ip_interface("{0}/{1}".format(
                                    curr_address['ifa-local'],
                                    subnet,
                                ))
                            except KeyError:
                                # No subnet is set so this is a host address
                                interface_addr = ipaddress.ip_interface("{0}".format(
                                    curr_address['ifa-local']))

                            if interface_addr.version == 6:
                                # Skip link local addresses
                                if interface_addr in self._link_local_subnet:
                                    continue

                            ip_addresses.append(drivers.base.IPAddress(
                                address=interface_addr,
                                vrf=None,
                                status='active',
                                interface=f"{curr_logical_int['name']}",
                            ))

        return ip_addresses

    def get_routes():

        routes = []

        # Fetch static
        # Fetch aggregate
        # Fetch access
        # Fetch anchor

        return routes











