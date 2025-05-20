# netbox-device-sync


## Install

```bash
python3 -m pip install -r requirements.txt
```

### Custom fields in netbox

* Discovered MACs
    * Object Types: IPAM > IP Addresses
    * Name: discovered_mac
    * Label: Discovered MAC
    * Description: "Matching MACs when the device is not in netbox"
    * Type: Multiple objects
    * Related object type: DCIM > MAC Address

## Configure

Copy config-example.py to config.py

```bash
cp config-example.py config.py
```


## Notes

### MAC Addresses

1. Since netbox 4.2 MACs are independencty managed objects (compared with strings before). This now enforces uniqueness as well as other constraints, one of which is the MAC can only be assigned to one interface at once. This creates a bit of an issue for all of the virtual interface types which take their MAC from the physical interfaces they depend on (A lag or bridge's MAC is one of the slave devices, vlans take their parent).
    a. As such for now MAC addresses for all virtual interfaces.
