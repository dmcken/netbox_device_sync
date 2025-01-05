'''Device sync script.

The main CLI sits here.



'''

# System imports
import argparse
import ipaddress
import logging
import pprint
import sys
import traceback

# External imports
import pynetbox

# Local imports
import config
import drivers.base
import drivers.edgeos
import drivers.junos
import drivers.routeros
import utils

logger = logging.getLogger(__name__)

def interface_create(nb: pynetbox.api, device_nb, cleaned_params, curr_dev_interface):

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

    logger.info(
        f"Creating '{curr_dev_interface.name}' on "
        f"'{device_nb.name}' => {cleaned_params}"
    )
    try:
        nb.dcim.interfaces.create(device=device_nb.id, **cleaned_params)
    except pynetbox.core.query.RequestError as exc:
        logger.error(
            f"Netbox API Error '{exc}' creating interface "
            f"{cleaned_params}/{device_nb.name}"
        )

def interface_update(nb: pynetbox.api, device_nb, nb_interface_dict, curr_dev_interface,
                     cleaned_params: dict[str,str]):


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
                old_parent_desc = f"{k_attr.id}/{nb_parent_interfaces[0].name}"
            else:
                old_parent_desc = "None"

            if new_parent_desc != old_parent_desc:
                changed[k] = {
                    'old': old_parent_desc,
                    'new': new_parent_desc,
                }
                setattr(curr_nb_obj, k, new_parent)
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
            interface_create(
                nb,
                device_nb,
                cleaned_params,
                curr_dev_interface,
            )

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
    for curr_network in utils.networks_to_ignore:
        dev_ips = list(filter(lambda x: x.address not in curr_network, dev_ips))
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

    # Now we need to check for those that need to be removed from netbox
    to_del = set(nb_ipaddresses_dict.keys()).difference(set(map(lambda x: x.address, dev_ips)))
    for curr_to_del in to_del:
        logger.info(
            f"Deleting IP record: {nb_ipaddresses_dict[curr_to_del].id}"
            f"/{nb_ipaddresses_dict[curr_to_del].address}"
        )
        nb_ipaddresses_dict[curr_to_del].delete()

    return

def setup_logging(args: argparse.Namespace) -> None:
    """Setup logging.

    Args:
        args (argparse.Namespace): CLI arguments passed to app.
    """
    # Upstream libraries
    logging.getLogger('ncclient').setLevel(logging.ERROR)
    logging.getLogger('paramiko.transport').setLevel(logging.ERROR)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
    # Internal modules
    logging.getLogger('__main__').setLevel(logging.INFO)
    logging.getLogger('drivers.edgeos').setLevel(logging.ERROR)
    if args.debug is True:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(
        level = log_level,
        format=config.LOGGING_FORMAT,
    )

def parse_arguments() -> argparse.Namespace:
    """Parse arguments.
    """
    parser = argparse.ArgumentParser(
        prog="Netbox device syncer",
        description="",
    )

    parser.add_argument('-d','--debug', action='store_true')

    args = parser.parse_args()
    return args

def main() -> None:
    '''Main sync function.
    '''
    args = parse_arguments()
    setup_logging(args)

    nb_api = pynetbox.api(
        config.NB_URL,
        token=config.NB_TOKEN,
        threading = True
    )

    # How best to make this dynamic (likely factory method)
    # Drivers for use to fetch the data from devices:
    # - EdgeRouter
    platform_to_driver = {
        'JunOS':            drivers.junos.JunOS,
        'RouterOS':         drivers.routeros.RouterOS,
        'Ubiquiti EdgeOS':  drivers.edgeos.EdgeOS,
    }

    device_credentials = utils.parse_device_parameters(config)

    # Fetch and process the devices from netbox.
    devices = nb_api.dcim.devices.all()

    for device_nb in devices:
        # Filter devices we can't or don't want to process.

        # Filter the device roles we don't want to probe.
        if device_nb.role.slug in utils.device_roles_to_ignore:
            logger.debug(f"Skipping device due to role: {device_nb.name}")
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
        # This should be provided via CLI arguments.
        # if device_nb.name not in []:
        #     continue

        try:
            # Build the driver and connect to the device
            # Create a driver passing it the credentials and the primary IP
            try:
                driver = platform_to_driver[str(device_nb.platform)]
            except KeyError as exc:
                raise drivers.base.ConnectError(
                    f"Unsupported platform '{device_nb.platform}'"
                ) from exc

            device_ip = str(ipaddress.ip_interface(device_nb.primary_ip).ip)
            full_dev_creds = {**device_credentials, 'hostname': device_ip}
            device_conn = driver(**full_dev_creds)

            # Now to sync the data
            sync_interfaces(nb_api, device_nb, device_conn)
            sync_ips(nb_api, device_nb, device_conn)

            # To Sync
            # - Vlans - Only for devices in charge of the vlan domain
            # - Static routes - Use to update prefixes
            # - Neighbour data (LLDP / CDP) - For building neighbour relations
            #   and rough cable plant.

            # sync_vlans()
            # sync_routes(nb, device_nb, device_conn)
            # sync_neighbours(nb, device_nb, device_conn)
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

    logger.info("Done")

if __name__ == '__main__':
    main()
