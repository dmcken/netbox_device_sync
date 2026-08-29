'''Driver for Ubiquiti AirOSv8 devices (Rocket Prism, PowerBeam,
NanoStation, ...) - see ubnt_automata.AirOSv8 and
drivers/_ubnt_cgi_common.py (the actual get_interfaces()/
get_ipaddresses() implementation, shared with AirFiber).
'''
# External imports
import ubnt_automata

# Local imports
import drivers._ubnt_cgi_common


class AirOS(drivers._ubnt_cgi_common.UbntCgiDriverBase):
    '''AirOSv8 device driver.'''

    _device_class = ubnt_automata.AirOSv8
