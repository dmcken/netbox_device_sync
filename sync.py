'''Device sync script.

The main CLI sits here.



'''

# System imports
import argparse
import ipaddress
import logging
import os
import pprint
import re
import sys
import traceback

# External imports
import dotenv
import pynetbox

# Local imports
import drivers.airfiber
import drivers.airos
import drivers.base
import drivers.edgeos
import drivers.junos
import drivers.routeros
import drivers.uisp
import utils

dotenv.load_dotenv()

LOGGING_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# NetBox's wireless-category Interface.type values - rf_role/rf_channel_*
# can only be set on an interface whose type is one of these.
_WIRELESS_INTERFACE_TYPES = {
    'ieee802.11a', 'ieee802.11g', 'ieee802.11n', 'ieee802.11ac',
    'ieee802.11ad', 'ieee802.11ax', 'ieee802.11ay', 'ieee802.11be',
    'other-wireless',
}

# Manual cabling-documentation convention already in use fleet-wide, e.g.
# an interface description of "FIB-IE1 [sfp-sfpplus1]" means the far end
# of the cable is that device's named port. Matched as a prefix, not the
# whole description - confirmed live that some descriptions have trailing
# text after the bracket (e.g. "DAN-SW0031 [sfp-sfpplus2] / Was Roylances
# UXG"). See sync_cable_descriptions().
_CABLE_DESC_RE = re.compile(r'^([^\[\]]+?)\s*\[([^\[\]]+)\]')

logger = logging.getLogger(__name__)

def interface_create(nb: pynetbox.api, device_nb, cleaned_params, curr_dev_interface) -> None:
    """Create an interface on a device.

    Args:
        nb (pynetbox.api): _description_
        device_nb (_type_): _description_
        cleaned_params (_type_): _description_
        curr_dev_interface (_type_): _description_
    """

    if 'type' not in cleaned_params:
        # Type is mandatory
        cleaned_params['type'] = 'other'

    for master_interface in ['bridge','lag','parent']:
        if master_interface in cleaned_params and \
            cleaned_params[master_interface] is not None:
            nb_parent_interfaces = list(
                nb.dcim.interfaces.filter(
                    device=device_nb.name,
                    name=cleaned_params[master_interface],
                )
            )
            try:
                cleaned_params[master_interface] = nb_parent_interfaces[0].id
            except (IndexError, KeyError, AttributeError):
                logger.error(
                    f"Unable to fetch parent interface '{device_nb.name}'"
                    f" => '{cleaned_params[master_interface]}'"
                )
                cleaned_params[master_interface] = None

    if 'mac_addresses' in cleaned_params:
        cleaned_params['mac_addresses'] = map(lambda x: x.id, cleaned_params['mac_addresses'])

    logger.info(
        f"Creating '{curr_dev_interface.name}' on "
        f"'{device_nb.name}' => {cleaned_params}"
    )
    try:
        curr_nb_obj = nb.dcim.interfaces.create(device=device_nb.id, **cleaned_params)
    except pynetbox.core.query.RequestError as exc:
        logger.error(
            f"Netbox API Error '{exc}' creating interface "
            f"{cleaned_params}/{device_nb.name}"
        )
        return None

    return curr_nb_obj

def interface_update(nb: pynetbox.api, device_nb, nb_interface_dict, curr_dev_interface,
                     cleaned_params: dict[str,str]):
    """Update a device interface.

    Args:
        nb (pynetbox.api): _description_
        device_nb (_type_): _description_
        nb_interface_dict (_type_): _description_
        curr_dev_interface (_type_): _description_
        cleaned_params (dict[str,str]): _description_
    """

    curr_nb_obj = nb_interface_dict[curr_dev_interface.name]
    changed = {}
    for k,v in cleaned_params.items():
        # Only update if different

        # Type's get has the value in type.value vs type itself.
        # Ugly hack for now.
        if k == 'type':
            if curr_nb_obj.type.value != v:
                changed[k] = {
                    'old': str(curr_nb_obj.type.value),
                    'new': v,
                }
                curr_nb_obj.type = v
        elif k in ['bridge','lag','parent']:
            new_parent = None
            if v:
                try:
                    nb_parent_interfaces = list(
                        nb.dcim.interfaces.filter(device=device_nb.name,name=v)
                    )
                    new_parent_desc = f"{nb_parent_interfaces[0].id}/{v}"
                    new_parent = nb_parent_interfaces[0].id
                except IndexError:
                    logger.error(
                        f"Could not look up parent interface for '{curr_dev_interface} => {v}"
                    )
                    continue
            else: # The parent interface is None
                new_parent_desc = f"{v}"


            if k_attr := getattr(curr_nb_obj, k):
                old_parent_desc = f"{k_attr.id}/{k_attr.name}"
            else:
                old_parent_desc = "None"

            if new_parent_desc != old_parent_desc:
                changed[k] = {
                    'old': old_parent_desc,
                    'new': new_parent_desc,
                }
                setattr(curr_nb_obj, k, new_parent)
        elif k == 'mac_addresses':
            # v is going to be the list of MAC address objects
            # getattr(curr_nb_obj, k) will be the list of nb MACs
            nb_macs = set(getattr(curr_nb_obj, k))
            to_add = set(v).difference(nb_macs)
            to_del = nb_macs.difference(set(v))
            final_list = list(nb_macs) + list(to_add)
            if to_add:
                changed[k] = {
                    'old': getattr(curr_nb_obj, k),
                    'new': final_list
                }
                curr_nb_obj.mac_addresses.extend(to_add)
            if to_del:
                logger.info(f"MACs to delete: {to_del}")
        elif getattr(curr_nb_obj,k) != v:
            changed[k] = {
                'old': getattr(curr_nb_obj,k),
                'new': v,
            }
            setattr(curr_nb_obj, k, v)

    if changed:
        logger.info(
            f"Updating '{curr_dev_interface.name}' on '{device_nb.name}' " +
            f"=> {pprint.pformat(changed)}"
        )
        curr_nb_obj.save()

def fetch_nb_mac(nb: pynetbox.api, mac_str: str) -> pynetbox.core.response.Record:
    """Fetch a netbox MAC address, creating if neccesary.

    Args:
        nb (pynetbox.api): Existing pynetbox API object.
        mac_str (str): MAC address in string format to fetch.

    Returns:
        pynetbox.core.response.Record: DCIM > MAC Address object.
    """
    if mac_str in ['00:00:00:00:00:00']:
        return None

    # Netbox stores/normalizes mac addresses as upper-case, but drivers
    # typically report them lower-case, so filtering/creating without
    # normalizing first would never match an existing record.
    mac_str = utils.clean_mac(mac_str)

    result = list(nb.dcim.mac_addresses.filter(mac_address=mac_str))
    if result:
        return result[0]

    # It doesn't exist, create it
    logger.info(f"Creating MAC: {mac_str}")
    obj = nb.dcim.mac_addresses.create(
        mac_address=mac_str
    )

    return obj

def set_interface_macs(dev_interface, nb_interface, nb) -> None:
    """Set MACs on the interfaces

    Args:
        curr_dev_interface (_type_): Driver interface object.
        nb_interface (_type_): Netbox interface object.
        nb (_type_): Netbox API object.
    """
    logger.debug(f"Entered set_interface_macs {dev_interface} => {nb_interface}")

    # MAC addresses are now related items
    mac_data = list(filter(
        lambda x: x not in utils.macs_to_ignore,
        getattr(dev_interface, 'mac_address', []),
    ))

    if not mac_data:
        return

    if dev_interface.type in ['bridge','lag','loopback','virtual']:
        logger.debug(f"Skipping setting MAC on interface {dev_interface.name}")
        return
    nb_mac_objs = []
    for curr_mac in mac_data:
        nb_mac_objs.append(fetch_nb_mac(nb, curr_mac))

    for curr_mac in nb_mac_objs:
        if curr_mac is None:
            continue
        changes = {}
        # Set mac.assigned_object_type to 'dcim.interface'
        if curr_mac.assigned_object_type != 'dcim.interface':
            changes['assigned_object_type'] = {
                'old': curr_mac.assigned_object_type,
                'new': 'dcim.interface',
            }
            curr_mac.assigned_object_type = 'dcim.interface'

        # Set mac.assigned_object_id to nb_interface.id
        if curr_mac.assigned_object_id != nb_interface.id:
            changes['assigned_object_id'] = {
                'old': curr_mac.assigned_object_id,
                'new': nb_interface.id,
            }
            curr_mac.assigned_object_id = nb_interface.id

        if changes:
            try:
                update_result = curr_mac.save()
                logger.info(f"Updating MAC '{curr_mac}' => {changes} => {update_result}")
            except pynetbox.core.query.RequestError as exc:
                logger.error(f"Error: {exc} assigning {curr_mac} to {nb_interface}")
                continue

    # Now set the primary MAC on the interface.
    try:
        if nb_interface.primary_mac_address != nb_mac_objs[0].id:
            nb_interface.primary_mac_address = nb_mac_objs[0].id
            nb_interface.save()
    except pynetbox.core.query.RequestError as exc:
        logger.error(f"Error: {exc} assigning primary {nb_mac_objs[0]} to "
                        f"{nb_interface} of type {nb_interface.type.value}")
    except AttributeError:
        # nb_mac_objs can be an empty list
        pass


def sync_interfaces(nb: pynetbox.api, device_nb, device_conn: drivers.base.DriverBase) -> None:
    """Sync interfaces to devices.

    Args:
        nb (pynetbox.api): pynetbox API instance.
        device_nb (_type_): The device from netbox's perspective.
        device_conn (drivers.base.DriverBase): _description_
    """
    # - Interfaces:
    # -- flag the routing instance / logical systems (use VRF to keep track of this)
    # -- On SRXes use tags to flag the security-zones
    nb_interfaces = nb.dcim.interfaces.filter(device=device_nb.name)
    nb_interface_dict = {v.name:v for v in nb_interfaces}
    nb_interfaces_names = set(map(lambda x: x.name, nb_interfaces))
    dev_interfaces = device_conn.get_interfaces()
    dev_interfaces_names = set(map(lambda x: x.name, dev_interfaces))
    # logger.info("Interface data for '{0}'\n{1}".format(device_nb.name,
    # pprint.pformat(dev_interfaces, width=200)))

    to_add_to_netbox     = sorted(list(dev_interfaces_names.difference(nb_interfaces_names)))
    to_check_for_updates = sorted(list(nb_interfaces_names.intersection(dev_interfaces_names)))
    to_delete_from_nb    = sorted(list(nb_interfaces_names.difference(dev_interfaces_names)))
    logger.debug(
        f"\nAdd: {to_add_to_netbox}\nDel: {to_delete_from_nb}\nUpdate: {to_check_for_updates}"
    )

    for curr_dev_interface in dev_interfaces:
        cleaned_params = {}
        for curr_param, param_data in utils.interface_fields_to_sync.items():
            # Skip for now
            if curr_param == 'mac_address':
                continue

            cleaned_params[curr_param] = getattr(curr_dev_interface, curr_param)
            if cleaned_params[curr_param] is None:
                del cleaned_params[curr_param]
                continue

            # Use extra meta data in param_data to perform additional cleaning.
            if 'clean' in param_data:
                cleaned_params[curr_param] = param_data['clean'](cleaned_params[curr_param])

        if curr_dev_interface.name in nb_interface_dict:
            interface_update(
                nb,
                device_nb,
                nb_interface_dict,
                curr_dev_interface,
                cleaned_params,
            )
        else:
            nb_interface_obj = interface_create(
                nb,
                device_nb,
                cleaned_params,
                curr_dev_interface,
            )
            if nb_interface_obj:
                nb_interface_dict[curr_dev_interface.name] = nb_interface_obj


        set_interface_macs(curr_dev_interface, nb_interface_dict[curr_dev_interface.name], nb)

    # Delete extra interfaces in netbox that are no longer on the device.
    nb_interfaces_to_delete = filter(lambda x: x.name in to_delete_from_nb, nb_interfaces)
    for curr_int_to_delete in nb_interfaces_to_delete:
        curr_int_to_delete.delete()

def create_ip_address(nb: pynetbox.api, curr_ip, nb_interface_dict) -> None:
    """Create IP address.

    Args:
        nb (_type_): _description_
        curr_ip (_type_): _description_
        nb_interface_dict (_type_): _description_
    """
    logger.info(f"Creating IP record: {curr_ip}")
    nb.ipam.ip_addresses.create(
        assigned_object_id=nb_interface_dict[curr_ip.interface].id,
        assigned_object_type='dcim.interface',
        address=str(curr_ip.address),
        status=curr_ip.status,
        vrf=curr_ip.vrf,
    )
    return

def update_ip_address(curr_ip, nb_ip_record, nb_interface_dict) -> None:
    """Update IP address in netbox.

    Args:
        curr_ip (_type_): _description_
        nb_ip_record (_type_): _description_
        nb_interface_dict (_type_): _description_
    """
    logger.debug(f"Checking IP record for changes: {curr_ip}")
    if len(nb_ip_record) == 1:
        changed = False

        if nb_ip_record[0].assigned_object_id != nb_interface_dict[curr_ip.interface].id or \
            nb_ip_record[0].assigned_object_type != 'dcim.interface':
            logger.info(
                f"Updating IP interface from '{nb_ip_record[0].assigned_object_type}':"
                f"{nb_ip_record[0].assigned_object_id} -> "
                f"{nb_interface_dict[curr_ip.interface].id}"
            )
            nb_ip_record[0].assigned_object_id = nb_interface_dict[curr_ip.interface].id
            nb_ip_record[0].assigned_object_type = 'dcim.interface'
            changed = True

        if nb_ip_record[0].status.value != curr_ip.status:
            logger.info(f"Updating status: {nb_ip_record[0].status.value} -> {curr_ip.status}")
            nb_ip_record[0].status = curr_ip.status
            changed = True

        if nb_ip_record[0].vrf != curr_ip.vrf:
            nb_ip_record[0].vrf = curr_ip.vrf
            logger.info("Updating vrf")
            changed = True

        if changed:
            logger.info(f"Updating IP record: {curr_ip} -> {changed}")
            nb_ip_record[0].save()
    else:
        logger.error(f"Multiple IPs found for: {curr_ip.address}")

    return

def sync_ips(nb_api: pynetbox.api, device_nb, device_conn: drivers.base.DriverBase) -> None:
    """Sync IP addresses.

    Args:
        nb_api (_type_): Netbox API connection.
        device_nb (_type_): _description_
        device_conn (_type_): _description_
    """

    # - IP Addresses - The matching interfaces should already exist (create the matching prefixes)
    dev_ips = device_conn.get_ipaddresses()
    for curr_network_to_ignore in utils.networks_to_ignore:
        dev_ips = list(filter(
            lambda x: x.address not in curr_network_to_ignore, dev_ips
        ))
    logger.debug(
        f"Raw IP data for '{device_nb.name}'\n" +
        f"{pprint.pformat(dev_ips, width=200)}"
    )

    # We need the interfaces to map the interface name to the netbox id.
    nb_ipaddresses = list(nb_api.ipam.ip_addresses.filter(device=device_nb.name))
    nb_ipaddresses_dict = {ipaddress.ip_interface(v.address):v for v in nb_ipaddresses}
    nb_interfaces = list(nb_api.dcim.interfaces.filter(device=device_nb.name))
    nb_interface_dict = {v.name:v for v in nb_interfaces}
    nb_interface_id_list = list(map(lambda x: x.id, nb_interfaces))

    for curr_ip in dev_ips:
        try:
            logger.debug(f"Processing IP address: {curr_ip}")
            if curr_ip.interface not in nb_interface_dict:
                logger.error(f"Missing interface for IP: {curr_ip}")
                continue

            nb_ip_network = nb_api.ipam.prefixes.filter(prefix=str(curr_ip.address.network))
            if not nb_ip_network:
                logger.error(f"Creating prefix: {curr_ip.address.network}")
                nb_api.ipam.prefixes.create(
                    prefix=f"{curr_ip.address.network}",
                    vrf=curr_ip.vrf,
                    status='active',
                )

            nb_ip_record = list(nb_api.ipam.ip_addresses.filter(address=curr_ip.address))
            if nb_ip_record:
                # We only want to update if its on the same device or not assigned to anything.
                if nb_ip_record[0].assigned_object_type is None or \
                    (nb_ip_record[0].assigned_object_type == 'dcim.interface' \
                    and nb_ip_record[0].assigned_object_id in nb_interface_id_list):
                    update_ip_address(curr_ip, nb_ip_record, nb_interface_dict)
                else:
                    create_ip_address(nb_api, curr_ip, nb_interface_dict)
            else:
                create_ip_address(nb_api, curr_ip, nb_interface_dict)
        except pynetbox.core.query.RequestError as exc:
            logger.error(f"Error processing {curr_ip} => {exc}")

    # Now we need to check for those that need to be removed from netbox
    to_del = set(nb_ipaddresses_dict.keys()).difference(set(map(lambda x: x.address, dev_ips)))
    for curr_to_del in to_del:
        logger.info(
            f"Deleting IP record: {nb_ipaddresses_dict[curr_to_del].id}"
            f"/{nb_ipaddresses_dict[curr_to_del].address}"
        )
        nb_ipaddresses_dict[curr_to_del].delete()

    return

def sync_site_gps(nb_api: pynetbox.api, device_nb, device_conn: drivers.base.DriverBase) -> None:
    """Backfill a Site's GPS location from a device with built-in GPS.

    Only fills in Sites with no coordinates set at all - never
    overwrites an existing value, whether that's a manually-entered one
    or one already backfilled from another device at the same site.

    Args:
        nb_api (pynetbox.api): Netbox API connection.
        device_nb (_type_): The device from netbox's perspective.
        device_conn (drivers.base.DriverBase): _description_
    """
    if device_nb.site is None:
        return

    gps = device_conn.get_gps()
    if gps is None:
        return

    site = nb_api.dcim.sites.get(id=device_nb.site.id)
    if site.latitude is not None or site.longitude is not None:
        return

    logger.info(
        f"Setting GPS for site '{site.name}' from '{device_nb.name}': "
        f"{gps.latitude}, {gps.longitude}"
    )
    site.latitude = gps.latitude
    site.longitude = gps.longitude
    site.save()

def _map_auth_type(security: str) -> str | None:
    """Map a device's raw wireless security string to NetBox's auth_type
    vocabulary (open/wep/wpa-personal/wpa-enterprise).

    Confirmed live: AirOS/AirFiber report e.g. "WPA-PSK"/"WPA2", UISP
    reports e.g. "wpa2" - none of the devices synced this pass exposed
    an explicit "enterprise"/802.1X indicator, so this only ever maps to
    open/wep/wpa-personal. Returns None (leave unset) rather than
    guessing for anything else.
    """
    if not security:
        return None

    security_upper = security.upper()
    if 'ENTERPRISE' in security_upper:
        return 'wpa-enterprise'
    if 'WPA' in security_upper:
        return 'wpa-personal'
    if 'WEP' in security_upper:
        return 'wep'
    if security_upper in ('NONE', 'OPEN', 'DISABLED'):
        return 'open'
    return None

def _find_interface_by_mac(nb_api: pynetbox.api, mac_str: str):
    """Find the NetBox interface a MAC address is currently assigned to.

    Read-only lookup, unlike fetch_nb_mac() - a peer's MAC not already
    known to NetBox just means that device isn't tracked yet, not
    something to create a bare MAC record for.

    Args:
        nb_api (pynetbox.api): Netbox API connection.
        mac_str (str): MAC address to look up.

    Returns:
        The interface record, or None if the MAC is unknown or isn't
        currently assigned to any interface.
    """
    mac_obj = nb_api.dcim.mac_addresses.get(mac_address=utils.clean_mac(mac_str))
    if mac_obj is None or mac_obj.assigned_object_type != 'dcim.interface':
        return None

    return nb_api.dcim.interfaces.get(id=mac_obj.assigned_object_id)

def _ensure_wireless_type(nb_interface) -> None:
    """NetBox rejects rf_role/rf_channel_*, and rejects a WirelessLink/
    WirelessLAN membership entirely, on an interface whose own `type`
    isn't already one of its wireless PHY types (confirmed live:
    {'rf_role': ['Wireless role may be set only on wireless
    interfaces.']} and {'interface_b': ['Other is not a wireless
    interface.']}). Sets the generic 'other-wireless' rather than
    guessing a specific 802.11 standard, and only when the type isn't
    already a wireless one (don't clobber a more specific value someone
    already set).
    """
    curr_type = nb_interface.type.value if nb_interface.type else None
    if curr_type not in _WIRELESS_INTERFACE_TYPES:
        nb_interface.type = 'other-wireless'
        nb_interface.save()

def _best_matching_wireless_interface(nb_api: pynetbox.api, peer_interface, expected_frequency_mhz):
    """Disambiguate which of a peer device's wireless interfaces a MAC
    match actually refers to.

    Confirmed live on Wave Pro/LR dual-radio hardware: both of a
    device's wireless-type interfaces (its 60 GHz "main" and 5 GHz
    "backup" radio) report the *identical* MAC, so a MAC-only lookup
    can resolve to the wrong one of the pair (whichever interface
    happened to keep that shared MAC when interfaces were originally
    synced) - confirmed live to actually pair a 66960 MHz local radio
    with a peer interface still carrying its sibling's 5260 MHz.

    Self-corrects across runs rather than needing to be right the first
    time: once both ends of a link have been synced at least once, each
    interface's own rf_channel_frequency is already populated, so this
    can prefer whichever sibling wireless interface on the peer's
    device is actually closest in frequency to the radio being linked,
    rather than trusting the MAC match blindly. On a device's first-
    ever sync there's nothing populated yet to compare against, so this
    falls back to the naive MAC match for that one pass.
    """
    if not expected_frequency_mhz:
        return peer_interface

    wireless_siblings = [
        i for i in nb_api.dcim.interfaces.filter(device_id=peer_interface.device.id)
        if i.type and i.type.value in _WIRELESS_INTERFACE_TYPES and i.rf_channel_frequency
    ]
    if len(wireless_siblings) <= 1:
        return peer_interface

    return min(
        wireless_siblings,
        key=lambda i: abs(i.rf_channel_frequency - expected_frequency_mhz),
    )

def _find_wireless_link(nb_api: pynetbox.api, interface_a, interface_b):
    """Find an existing WirelessLink connecting two interfaces, in
    either order - either side's sync run could have created it first.
    """
    for link in nb_api.wireless.wireless_links.filter(interface_a_id=interface_a.id):
        if link.interface_b.id == interface_b.id:
            return link

    for link in nb_api.wireless.wireless_links.filter(interface_a_id=interface_b.id):
        if link.interface_b.id == interface_a.id:
            return link

    return None

def _sync_wireless_link(
    nb_api: pynetbox.api, device_nb, nb_interface, radio: drivers.base.WirelessRadio,
    auth_type: str | None,
) -> None:
    """Sync a point-to-point wireless link (a radio with exactly one
    currently-linked peer) - find-or-create its WirelessLink and fill
    in whichever of ssid/auth_type/auth_psk are currently empty.
    status is always set to 'connected', since reaching this code path
    at all means the device reports a live peer right now - unlike
    ssid/auth, that's an observation, not a fact someone might have
    deliberately set differently by hand.
    """
    peer = radio.peers[0]
    peer_interface = _find_interface_by_mac(nb_api, peer.mac)
    if peer_interface is None:
        logger.warning(
            f"Could not match PtP peer '{peer.hostname}' ({peer.mac}) for "
            f"'{device_nb.name}'/{radio.interface} to any NetBox interface"
        )
        return

    if peer_interface.device.id == device_nb.id:
        # A stale/self-referential MAC assignment - not a real peer.
        return

    peer_interface = _best_matching_wireless_interface(
        nb_api, peer_interface, radio.frequency_mhz,
    )
    _ensure_wireless_type(peer_interface)

    link = _find_wireless_link(nb_api, nb_interface, peer_interface)
    if link is None:
        link = nb_api.wireless.wireless_links.create(
            interface_a=nb_interface.id,
            interface_b=peer_interface.id,
        )
        logger.info(
            f"Created WirelessLink '{device_nb.name}'/{radio.interface} <-> "
            f"'{peer_interface.device.name}'/{peer_interface.name}"
        )

    changed = {}
    if not link.ssid and radio.ssid:
        changed['ssid'] = radio.ssid
    if not link.status or link.status.value != 'connected':
        changed['status'] = 'connected'
    if auth_type and (not link.auth_type or link.auth_type.value != auth_type):
        changed['auth_type'] = auth_type
    if radio.psk and not link.auth_psk:
        changed['auth_psk'] = radio.psk

    if changed:
        for key, value in changed.items():
            setattr(link, key, value)
        link.save()
        logger.info(f"Updated WirelessLink {link.id}: {list(changed.keys())}")

def _sync_wireless_lan(
    nb_api: pynetbox.api, device_nb, nb_interface, radio: drivers.base.WirelessRadio,
    auth_type: str | None,
) -> None:
    """Sync a point-to-multipoint network (a radio with more than one
    currently-linked peer) - find-or-create its WirelessLAN (keyed on
    ssid), associate this AP's own interface, and associate whichever
    peers resolve to a NetBox interface.
    """
    if not radio.ssid:
        logger.error(
            f"PtMP AP '{device_nb.name}'/{radio.interface} has no ssid - "
            "can't find/create its WirelessLAN"
        )
        return

    wlan = next(iter(nb_api.wireless.wireless_lans.filter(ssid=radio.ssid)), None)
    if wlan is None:
        wlan = nb_api.wireless.wireless_lans.create(ssid=radio.ssid)
        logger.info(f"Created WirelessLAN '{radio.ssid}'")

    changed = {}
    if not wlan.status or wlan.status.value != 'active':
        changed['status'] = 'active'
    if auth_type and (not wlan.auth_type or wlan.auth_type.value != auth_type):
        changed['auth_type'] = auth_type
    if radio.psk and not wlan.auth_psk:
        changed['auth_psk'] = radio.psk

    if changed:
        for key, value in changed.items():
            setattr(wlan, key, value)
        wlan.save()
        logger.info(f"Updated WirelessLAN {wlan.id}: {list(changed.keys())}")

    if wlan.id not in [w.id for w in nb_interface.wireless_lans]:
        nb_interface.wireless_lans = [*[w.id for w in nb_interface.wireless_lans], wlan.id]
        nb_interface.save()

    for peer in radio.peers:
        peer_interface = _find_interface_by_mac(nb_api, peer.mac)
        if peer_interface is None:
            logger.warning(
                f"Could not match PtMP peer '{peer.hostname}' ({peer.mac}) on "
                f"'{device_nb.name}'/{radio.interface} to any NetBox interface"
            )
            continue

        if peer_interface.device.id == device_nb.id:
            continue

        peer_interface = _best_matching_wireless_interface(
            nb_api, peer_interface, radio.frequency_mhz,
        )
        _ensure_wireless_type(peer_interface)

        existing_ids = [w.id for w in peer_interface.wireless_lans]
        if wlan.id not in existing_ids:
            peer_interface.wireless_lans = [*existing_ids, wlan.id]
            peer_interface.save()

def sync_wireless(nb_api: pynetbox.api, device_nb, device_conn: drivers.base.DriverBase) -> None:
    """Sync wireless frequency/channel data and PtP/PtMP connections.

    A radio with exactly one currently-linked peer is one end of a
    point-to-point link (WirelessLink); more than one peer means this
    device is the AP side of a point-to-multipoint network
    (WirelessLAN). Device is authoritative for rf_role/frequency/
    channel width - always updated. ssid/auth_type/auth_psk on an
    existing WirelessLink/WirelessLAN are only filled in if currently
    empty, so a value someone already set by hand for their own reason
    is never overwritten.

    Args:
        nb_api (pynetbox.api): Netbox API connection.
        device_nb (_type_): The device from netbox's perspective.
        device_conn (drivers.base.DriverBase): _description_
    """
    for radio in device_conn.get_wireless_radios():
        nb_interface = nb_api.dcim.interfaces.get(device=device_nb.name, name=radio.interface)
        if nb_interface is None:
            logger.error(
                f"Wireless radio interface '{radio.interface}' not found on "
                f"'{device_nb.name}' - was it created by sync_interfaces()?"
            )
            continue

        _ensure_wireless_type(nb_interface)

        changed = {}
        curr_rf_role = nb_interface.rf_role.value if nb_interface.rf_role else None
        if radio.role in ('ap', 'station') and curr_rf_role != radio.role:
            changed['rf_role'] = radio.role
        if radio.frequency_mhz and nb_interface.rf_channel_frequency != radio.frequency_mhz:
            changed['rf_channel_frequency'] = radio.frequency_mhz
        if radio.channel_width_mhz and nb_interface.rf_channel_width != radio.channel_width_mhz:
            changed['rf_channel_width'] = radio.channel_width_mhz

        if changed:
            for key, value in changed.items():
                setattr(nb_interface, key, value)
            nb_interface.save()
            logger.info(
                f"Updated wireless config on '{device_nb.name}'/{radio.interface}: {changed}"
            )

        if not radio.peers:
            continue

        auth_type = _map_auth_type(radio.security)
        if len(radio.peers) == 1:
            _sync_wireless_link(nb_api, device_nb, nb_interface, radio, auth_type)
        else:
            _sync_wireless_lan(nb_api, device_nb, nb_interface, radio, auth_type)

def sync_cable_descriptions(nb_api: pynetbox.api) -> None:
    """Create Cables from the "<Device> [<Port>]" manual cabling
    convention already used fleet-wide in interface descriptions - e.g.
    "FIB-IE1 [sfp-sfpplus1]" means the far end of this interface's
    cable is that device's named port.

    Not driven by any live device - this is pure NetBox metadata
    already entered by hand, so it's run once per sync.py invocation
    (not per-device like sync_interfaces()/sync_wireless()/etc.),
    scanning every interface in NetBox regardless of platform.

    If the named device or port doesn't exist, or either end already
    has a cable, the description is left alone and skipped - never
    treated as an error, since this convention predates (and partially
    overlaps with) actual Cable records already existing for some of
    these interfaces.
    """
    for interface in nb_api.dcim.interfaces.all():
        if not interface.description or interface.cable:
            continue

        match = _CABLE_DESC_RE.match(interface.description)
        if not match:
            continue

        remote_device_name = match.group(1).strip()
        remote_port_name = match.group(2).strip()

        # A single lookup covers both "ignore" conditions at once - a
        # nonexistent port on a real device just comes back as no result,
        # but confirmed live that a nonexistent *device* name makes
        # NetBox's own filter validation reject the whole request instead
        # of returning zero results, so that has to be caught too.
        try:
            remote_interface = nb_api.dcim.interfaces.get(
                device=remote_device_name, name=remote_port_name,
            )
        except pynetbox.core.query.RequestError:
            remote_interface = None

        if remote_interface is None:
            logger.debug(
                f"Cabling description '{interface.description}' on "
                f"'{interface.device.name}'/{interface.name} doesn't resolve "
                "to a real device/port - ignoring"
            )
            continue

        if remote_interface.id == interface.id or remote_interface.cable:
            continue

        try:
            nb_api.dcim.cables.create(
                a_terminations=[{'object_type': 'dcim.interface', 'object_id': interface.id}],
                b_terminations=[
                    {'object_type': 'dcim.interface', 'object_id': remote_interface.id}
                ],
                status='connected',
            )
        except pynetbox.core.query.RequestError as exc:
            # Most likely the other end's own pass through this same loop
            # already cabled it (both sides commonly carry matching
            # descriptions) - our in-memory copy just hadn't seen it yet.
            logger.debug(
                f"Could not create cable '{interface.device.name}'/{interface.name} <-> "
                f"'{remote_device_name}'/{remote_port_name}: {exc}"
            )
            continue

        logger.info(
            f"Created cable '{interface.device.name}'/{interface.name} <-> "
            f"'{remote_device_name}'/{remote_port_name}"
        )

def sync_neighbours(nb_api: pynetbox.api, device_nb, device_conn: drivers.base.DriverBase) -> None:
    """Sync neighbour data.

    Args:
        nb_api (pynetbox.api): _description_
        device_nb (_type_): _description_
        device_conn (drivers.base.DriverBase): _description_
    """

    dev_neighbours = device_conn.get_neighbours()

    for curr_neighbour in dev_neighbours:
        logger.debug(f"Syncronizing neighbour: {curr_neighbour}")
        # MAC is now a list
        nb_mac_objs = []
        for curr_mac in curr_neighbour.mac:
            nb_mac_objs.append(fetch_nb_mac(nb_api, curr_mac))

        # Fetch the IP record if it exists.
        ip_obj = list(nb_api.ipam.ip_addresses.filter(address=curr_neighbour.ip))

        if ip_obj:
            if ip_obj[0]['assigned_object_type'] == 'dcim.interface':
                # If it already exists and is assigned to a device, leave alone.
                continue
            else:
                # If not assigned to a device update any appropriate fields.
                logger.debug(f"Updating: {ip_obj}")
                continue

        # Create a new IP address record with the info we have.
        # Neighbour(
        #   mac='C0:8A:CD:D5:05:78',
        #   ip='10.32.232.3',
        #   name=None,
        #   interface='bond_v0060_CALIX_IPTV',
        #   source='ARP',
        #   extra_data=None
        # )
        logger.debug(f"Creating IP for {pprint.pformat(curr_neighbour)}")
        nb_api.ipam.ip_addresses.create(
            address=f"{curr_neighbour.ip}",
            description=f"{curr_neighbour.source}#{device_nb}#{curr_neighbour.interface}#{curr_neighbour.name}",
            # custom_fields={
            #     'discovered_mac': nb_mac_obj.id,
            # },
        )

def setup_logging(args: argparse.Namespace) -> None:
    """Setup logging.

    Args:
        args (argparse.Namespace): CLI arguments passed to app.
    """
    # Upstream libraries
    logging.getLogger('librouteros').setLevel(logging.ERROR)
    logging.getLogger('ncclient').setLevel(logging.ERROR)
    logging.getLogger('paramiko.transport').setLevel(logging.ERROR)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
    logging.getLogger('drivers.edgeos').setLevel(logging.ERROR)

    if args.debug is True:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    # Internal modules
    logging.getLogger('__main__').setLevel(log_level)


    logging.basicConfig(
        level = log_level,
        format=LOGGING_FORMAT,
    )

def parse_arguments() -> argparse.Namespace:
    """Parse arguments.
    """
    parser = argparse.ArgumentParser(
        prog="Netbox device syncer",
        description="",
    )

    parser.add_argument(
        '-d',
        '--debug',
        action='store_true',
        help="Activate debug mode with allot more output, mostly useful for troubleshooting issues."
    )

    parser.add_argument(
        '-n' ,'--netbox-device', nargs='+', default=[],
        help="Only process netbox devices specified, can be specified multiple times."
    )

    args = parser.parse_args()
    return args

def main() -> None:
    '''Main sync function.
    '''
    args = parse_arguments()
    setup_logging(args)
    logger.debug(f"CLI arguments: {pprint.pformat(args)}")

    nb_api = pynetbox.api(
        os.environ.get('NB_URL'),
        token=os.environ.get('NB_TOKEN'),
        threading = True
    )

    # How best to make this dynamic (likely factory method)
    # Drivers for use to fetch the data from devices:
    # - EdgeRouter
    platform_to_driver = {
        'JunOS':                drivers.junos.JunOS,
        'RouterOS':             drivers.routeros.RouterOS,
        'Ubiquiti EdgeRouter':  drivers.edgeos.EdgeOS,
        'AirOS v8':             drivers.airos.AirOS,
        'AirFiber':             drivers.airfiber.AirFiber,
        'UISP':                 drivers.uisp.Uisp,
    }

    device_credentials = utils.parse_device_parameters()

    # Fetch and process the devices from netbox.
    devices = nb_api.dcim.devices.all()

    for device_nb in devices:
        # Filter devices we can't or don't want to process.

        # Filter the device roles we don't want to probe.
        if device_nb.role.slug in utils.device_roles_to_ignore:
            logger.debug(f"Skipping device due to role: {device_nb.id}#{device_nb.name}")
            continue

        logger.debug(
            f"Processing device: {device_nb.id:04}/{device_nb.name}/{device_nb.role.slug}"
            f" => {device_nb.platform} => {device_nb.primary_ip}"
        )

        # Is the platform empty?
        # Is the primary IP not set?
        # Only process devices with acceptable statuses
        if device_nb.platform is None or \
           device_nb.primary_ip is None or \
           device_nb.status.value not in utils.acceptable_device_status:
            continue

        # Filter devices with specific names
        if args.netbox_device:
            if device_nb.name not in args.netbox_device:
                # logger.info(f"Skipping device due to device name: '{device_nb.name}'")
                continue

        # Set before anything that could raise, so the exception handlers below
        # always have a sane value to report even if it fails before being
        # refined into a plain address further down.
        device_ip = str(device_nb.primary_ip)
        try:
            logger.info(f"Processing: {device_nb.name}")
            # Build the driver and connect to the device
            # Create a driver passing it the credentials and the primary IP
            try:
                driver = platform_to_driver[str(device_nb.platform)]
            except KeyError:
                logger.error(f"Unsupported platform '{device_nb.platform}'")
                continue

            device_ip = str(ipaddress.ip_interface(device_nb.primary_ip).ip)
            full_dev_creds = {**device_credentials, 'hostname': device_ip}
            device_conn = driver(**full_dev_creds)

            # Now to sync the data
            sync_interfaces(nb_api, device_nb, device_conn)
            sync_ips(nb_api, device_nb, device_conn)
            sync_site_gps(nb_api, device_nb, device_conn)
            sync_wireless(nb_api, device_nb, device_conn)
            # sync_neighbours(nb_api, device_nb, device_conn)

            # To Sync
            # - Vlans - Only for devices in charge of the vlan domain
            # - Static routes - Use to update prefixes
            # - Neighbour data (LLDP / CDP) - For building neighbour relations
            #   and rough cable plant.

            # sync_vlans()
            # sync_routes(nb, device_nb, device_conn)
            del device_conn
        except drivers.base.ConnectError as exc:
            logger.error(
                f"There was an error connecting to '{device_ip}': {exc.__class__} => {exc}"
            )
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logger.error(pprint.pformat(
                traceback.format_exception(exc_type, exc_value, exc_traceback)
            ))
            continue
        # This is a last resort catcher, I want to catch and at least provide some
        # useful information before moving onto the next device.
        # pylint: disable=W0718
        except Exception as exc:
            logger.error(f"There was an error syncing '{device_ip}': {exc.__class__}, {exc}")
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logger.error(pprint.pformat(
                traceback.format_exception(exc_type, exc_value, exc_traceback)
            ))

    # Not driven by any live device - runs once against NetBox's existing
    # interface descriptions, not per-device like the sync above.
    sync_cable_descriptions(nb_api)

    logger.info("Done")

if __name__ == '__main__':
    main()
