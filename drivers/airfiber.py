'''Driver for Ubiquiti AirFiber devices (60 HD/LR/XR-predecessors, 5X
HD, ...) - see ubnt_automata.AirFiber and drivers/_ubnt_cgi_common.py
(the actual get_interfaces()/get_ipaddresses() implementation, shared
with AirOSv8).

Note: AirFiber 60 XR runs the UISP-firmware JSON REST API instead of
this .cgi API despite the AirFiber branding - see drivers/uisp.py and
ubnt_automata.UispDevice's own docstring for why.
'''
# External imports
import ubnt_automata

# Local imports
import drivers._ubnt_cgi_common


class AirFiber(drivers._ubnt_cgi_common.UbntCgiDriverBase):
    '''AirFiber device driver.'''

    _device_class = ubnt_automata.AirFiber
