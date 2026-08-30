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

Copy .env.example to .env and fill in your values.

```bash
cp .env.example .env
```


## Notes

### MAC Addresses

* Since netbox 4.2 MACs are managed objects (compared with strings before). This now enforces uniqueness as well as other constraints, one of which is the MAC can only be assigned to one interface at once. This creates a bit of an issue for all of the virtual interface types which take their MAC from the physical interfaces they depend on (A lag or bridge's MAC is one of the slave devices, vlans take their parent device's MAC address).
    * As such for now MAC addresses for all virtual interfaces will remain un-set

### Automatic device linking

Two independent conventions the sync recognises for connecting devices to
each other in NetBox - one wireless, one physical. Both only ever *add*
data (fill in whatever's currently empty); neither overwrites a value
someone already set by hand.

#### Wireless (WirelessLink / WirelessLAN)

* A radio is linked as **point-to-point** (`WirelessLink`) if it currently
  has exactly one linked peer, or as the **AP side of a point-to-multipoint**
  network (`WirelessLAN`) if it has more than one. Nothing to do if it has
  zero.
* A peer is matched to a NetBox interface by looking up its MAC address -
  read-only, never creates a bare MAC record just because a peer was seen.
  If the MAC doesn't resolve to any interface, that's logged as a visible
  **warning** (not an error) rather than silently dropped, since it usually
  means a customer CPE isn't tracked in NetBox yet - a real inventory gap
  worth surfacing. The local side's own radio still gets its fields set
  regardless of whether the peer resolved.
* **Always updated to match the device's live report** (device is
  authoritative, same as interfaces/IPs elsewhere in this tool): the
  interface's `type` (set to `other-wireless` if it isn't already one of
  NetBox's wireless PHY types - required before `rf_role`/`rf_channel_*`
  can be set at all), `rf_role`, `rf_channel_frequency`, `rf_channel_width`,
  and the `WirelessLink`'s `status` (`connected`, since reaching this code
  path at all means a live peer was just observed).
* **Only filled in if currently empty**: `ssid`, `auth_type`, `auth_psk` on
  the `WirelessLink`/`WirelessLAN`. `auth_type` is derived from the
  device's raw security string with a simple substring match (`PSK`/`WPA`
  -> `wpa-personal`, `WEP` -> `wep`, empty/`open`/`disabled` -> `open`,
  anything else left unset rather than guessed).
* Some dual-radio hardware (e.g. Wave Pro/LR's 60 GHz "main" + 5 GHz
  "backup" radios) reports the *identical* MAC on both of a device's
  wireless interfaces, so a MAC-only match can resolve to the wrong radio
  on the peer's end. This is corrected by preferring whichever sibling
  wireless interface on the peer's device already has a synced frequency
  closest to the one being linked - there's nothing to compare against on
  that peer's very first sync, so a brand new pair of devices may get
  mismatched for one run, then self-correct on the next.

#### Physical cabling (`Cable`)

* An interface `description` that starts with `"<Device name> [<Port
  name>]"` (e.g. `"FIB-IE1 [sfp-sfpplus1]"`) is read as a manual note that
  the far end of this cable is that device's named port - matched as a
  prefix, so any text after the closing bracket is ignored (some
  descriptions carry extra notes there already, e.g. `"DAN-SW0031
  [sfp-sfpplus2] / Was Roylances UXG"`).
* If the named device or port doesn't actually exist in NetBox, the
  description is silently ignored - never an error. Same if either end
  already has a cable connected (never replaces an existing one).
* Unlike everything else in this tool, this isn't driven by any live
  device - it only reads descriptions already entered by hand into
  NetBox - so it runs once per `sync.py` invocation against every
  interface in NetBox, regardless of platform, rather than per-device.

#### Subnet-inferred routed links (`Cable`)

Two more conventions, both opt-in via their own `.env` flag (off by
default) since they infer a cable's existence purely from IP layout
rather than reading any explicit "this connects to that" data. Both
skip an interface that already has a cable, same as everything else
above, and both only ever consider a **physical** port - a real,
single, cable-terminable interface (not `virtual`/`bridge`/`lag`, and
not a wireless radio). NetBox's `type` alone can't fully tell that apart
from a software construct - a tunnel interface (e.g. IPIP) has no
dedicated type of its own and just shows up as the generic `other`,
indistinguishable by type from a genuinely unclassified physical port -
so a real MAC address (something the device itself reported, which a
tunnel never has) is required too. If the IP is on a bridge or a
VLAN/virtual sub-interface instead of directly on a physical port, that
resolves one level up (the bridge's sole physical member, or the VLAN
interface's own parent) - but only when that resolves to *exactly one*
candidate. A router's bridge aggregating several physical uplink ports
at once (a switch fabric, confirmed live: one device's bridge had three
plausible physical members) is left alone rather than guessed, since
there's no LLDP or other data here to say which one a given cable is
actually in.

* **`ASSUME_SUBNET_LINKS_30_31`** - a /30 or /31 has exactly 2 usable
  host addresses, the standard point-to-point routed-link convention.
  Two physical ports (on two different devices) whose IPs land in the
  same one of these small subnets are assumed to be the two ends of one
  cable. This is blind subnet matching with no other corroborating
  evidence at all, so it's opt-in.
* **`ASSUME_SUBNET_LINKS_29`** - for backhaul point-to-point wireless
  pairs specifically (i.e. only devices already linked to each other via
  an existing `WirelessLink`, from the wireless sync above): this
  fleet's convention is to lay a backhaul link's own /29 out with both
  radios' bridge IPs *and* both sides' router IPs in the one block, with
  each side's router IP and radio IP numerically closer to each other
  than to the far side's. Sorting both the two already-known radio IPs
  and the two remaining ("router") IPs in the block and pairing them up
  in the same order recovers "same side" without hardcoding which
  octets belong to which end, then connects each backhaul's own physical
  ethernet uplink port to the router port on its own side. Much
  better-evidenced than the /30-/31 rule above (it only ever acts on a
  pair already confirmed live over the air), but still an assumption
  about which physical port that implies, so it has its own separate
  gate rather than sharing `ASSUME_SUBNET_LINKS_30_31`.
