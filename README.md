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

#### OSPF-inferred routed links (`ASSUME_OSPF_LINKS`)

A third opt-in cabling rule, currently only implemented for RouterOS
(`drivers/routeros.py`'s `get_ospf_neighbours()`, reading
`routing/ospf/neighbor`) - real routing-protocol evidence of a direct
link, rather than an inference from IP layout like the two rules above.

* Only ever acts on a local interface with exactly one distinct
  neighbour router ID currently in the `Full` adjacency state. A shared/
  broadcast segment (e.g. a "trunk" bridge aggregating several physical
  uplinks) can carry `Full` adjacencies to more than one neighbour at
  once on the same local interface - a single `Cable` can't represent
  that, so it's left alone entirely rather than guessed at.
* This fleet's convention is for each router's OSPF router ID to be its
  own loopback address. The neighbour's reported link address (its IP
  on this specific link, used to resolve which NetBox interface/device
  it is) and its router ID are cross-checked against each other -
  confirmed live that these can actually disagree (an IP address
  recorded in NetBox against the wrong device entirely). A mismatch is
  logged as a **warning** (a real data-quality issue worth surfacing)
  and skipped rather than trusting either value blindly.
* A router ID or address that falls in a known shared/non-unique
  convenience network (see `utils.networks_to_ignore` - e.g.
  `172.16.255.255/32`, confirmed live to sit identically on a
  `loopback1` interface across multiple independent routers) is skipped
  silently rather than reaching the cross-check above, since it can
  never uniquely identify a single neighbour device.
* OSPF runs happily over a VLAN/bridge interface, but NetBox `Cable`s
  can only terminate on a real physical port - both ends are resolved
  up to their physical port the same way as the `/29` rule above (giving
  up rather than guessing on an ambiguous multi-member bridge).

#### Client device auto-provisioning (`ASSUME_CLIENT_DEVICES`)

Unlike everything above, which only ever links or fills in fields on
Devices that already exist, this one creates brand-new Device/Interface
records - so it's off by default even more deliberately than the two
subnet-inference rules.

For the AP side of a point-to-multipoint `WirelessLAN` only (never a
point-to-point `WirelessLink` - that peer is expected to already be a
real, separately-managed device): a peer whose MAC doesn't resolve to
any existing NetBox interface is, on a platform with an entry in
sync.py's `_CLIENT_DEVICE_CONVENTIONS` (currently `Tachyon`, and all
three Ubiquiti-family platforms - `AirOS v8`/`AirFiber`/`UISP`),
auto-provisioned a placeholder client Device instead of just being
logged as an unresolved peer:

* Named `"<prefix><peer's reported name>"` - `"TACH-<name>"` for
  Tachyon (the name being e.g. `wireless.peers[].system_name` on a
  Tachyon radio), `"UBNT-<name>"` for Ubiquiti - either way it's
  exactly what the peer itself reports, not independently verified.
  Deliberately its own prefix, distinct from this fleet's pre-existing
  manual `CUST-<name>` customer-CPE convention (e.g. `CUST-Botany Honey
  Company`) - a real, manually-managed `CUST-` device was briefly
  modified by mistake by a cleanup script that scoped by name prefix
  instead of by `platform is None` + `role is CPE - Dish`, which is
  what actually, reliably identifies an auto-created placeholder. A
  distinct prefix means that's no longer the only way to tell.
* Device type is fuzzy-matched from the peer's own reported hardware
  model against existing NetBox device types for that platform's
  manufacturer, in *either* direction - a peer can report a more
  specific model than any registered type (Tachyon: `"TNA-303L-65"`
  matches the registered `"TNA-303"`, since no more specific
  `"TNA-303L"` type exists), or a less specific one (Ubiquiti: peers
  only ever report a base model like `"Rocket Prism 5AC"`, itself a
  prefix of the registered `"Rocket Prism 5AC Gen2"`). Only trusted when
  it resolves to *exactly one* candidate - confirmed live that the
  less-specific direction is often genuinely ambiguous (a peer
  reporting `"PowerBeam 5AC"` or `"NanoBeam 5AC"` matches several
  different registered variants - `5AC 300`/`5AC 500`/`5AC Gen2`, or
  `5AC 19`/`5AC Gen2` - at once). No match, or more than one, and the
  device isn't created - a warning is logged instead, same as an
  unresolved peer normally gets.
* Role `CPE - Dish`, site matching the AP's own site, status `active`.
* **`platform` is deliberately left unset** (matching every existing
  manually-created customer placeholder in this fleet already) - so
  this tool's own per-device sync loop never tries to poll it with
  credentials that aren't ours to use.
* Gets one `wlan0` interface holding the peer's MAC and IP addresses
  (recorded as host routes - `/32`/`/128` - since a peer only ever
  reports its own bare address, never the subnet it's part of; the same
  link-local/loopback ranges ignored everywhere else in this tool are
  skipped here too) - then treated exactly like a normally-resolved
  peer from there on (associated with the `WirelessLAN`, etc).

## Proxmox sync (`sync_proxmox.py`)

Models Proxmox VE clusters in NetBox: each guest (QEMU VM or LXC container,
templates skipped) becomes a NetBox virtual machine with its host node, status,
vCPUs, memory, SMBIOS UUID (serial), virtual disks, interfaces + MACs, guest IPs
and a primary IPv4. **Proxmox is authoritative** for every cluster the sync is
enabled on.

```
.venv/bin/python sync_proxmox.py --dry-run          # print every change, write nothing
.venv/bin/python sync_proxmox.py                     # all clusters with proxmox_sync_enabled
.venv/bin/python sync_proxmox.py -c DC1-Internal     # one cluster
```

### Per-cluster configuration (NetBox)

Custom fields on the NetBox **cluster** (group "Proxmox sync"):

| Field | Example | |
|---|---|---|
| `proxmox_sync_enabled` | true | include the cluster in runs |
| `proxmox_token_id` | `netbox@pve!sync` | |
| `proxmox_verify_tls` | false | false for self-signed node certificates |
| `proxmox_node_map` | `pve1=DC-DC1-PVE001,...` | optional, when node names don't match the NetBox devices |

There is no API URL to configure: the sync tries the **primary IP of each
device in the NetBox cluster** (port 8006, active devices first) and uses the
first node that answers, so any node being down is fine.

**Onboarding a cluster:** create the cluster in NetBox, add one of its hosts
(device) to it with a primary IP, set `proxmox_token_id` and
`proxmox_sync_enabled`, add the secret below, and run `--dry-run`.

The token **secret** is not stored in NetBox (custom fields are readable by
every NetBox user). Put it in `.env` as `PVE_TOKEN_SECRET_<CLUSTER>`: the NetBox
cluster name upper-cased, non-alphanumerics replaced by `_`
(`DC1-Internal` -> `PVE_TOKEN_SECRET_DC1_INTERNAL`).

Each VM also gets a `proxmox_vmid` custom field; the sync matches on it.

### Proxmox user and permissions (per cluster)

Run on any node of the cluster as root:

```
pveum user add netbox@pve --comment "NetBox sync"
pveum acl modify / --users netbox@pve --roles PVEAuditor
pveum role add NetBoxGuestAgent --privs "VM.Monitor"
pveum acl modify / --users netbox@pve --roles NetBoxGuestAgent
pveum user token add netbox@pve sync --privsep 0      # secret is shown once
```

`PVEAuditor` covers nodes, guests, configs and disks. **Guest IPs and OS**
come from the QEMU guest agent (`agent/network-get-interfaces`,
`agent/get-osinfo`), which on **Proxmox 8 requires `VM.Monitor`**. Be aware
that `VM.Monitor` also allows QEMU monitor commands on every VM, so this token
is not strictly read-only: keep the secret only in `.env` (mode 600). On
**Proxmox 9** replace `VM.Monitor` with `VM.GuestAgent.Audit`, which is
read-only. Without either, the sync still runs but VMs get no IPs, primary IP
or platform (the log warns "permission denied ... guest-agent calls").
VMs without the guest agent installed/enabled never get IPs.

### Hardware inventory (node serials, device types, iDRAC/iLO)

The Proxmox API has no DMI data, so for each node the sync also runs a fixed,
read-only command over SSH: `dmidecode` (manufacturer, model, service tag, BIOS)
and `ipmitool lan print 1` (BMC IP, mask, MAC). It connects to the node's
Proxmox cluster IP first and, if that fails (for example a corosync-only
network the sync host cannot route to), to the node device's NetBox primary
IP. From that it sets:

- the device **serial** (Dell service tag);
- the **device type**, but only on nodes the sync created (description starts
  "Created by sync_proxmox.py") and on "Generic ..." placeholders. Any other
  mismatch, or a model with no device type in NetBox, is a warning; import
  missing types from the devicetype-library rather than creating them by hand;
- the BMC interface (`iDRAC` / `iLO`, mgmt-only, created if missing) **MAC and
  IP**, and the device's **out-of-band IP**.

Access is a dedicated key (`~/.ssh/netbox_pve_inventory` on netbox001, override
with `PVE_SSH_KEY`). Print the line for a cluster with:

```
.venv/bin/python sync_proxmox.py --print-authorized-keys 172.16.17.10
```

and append it, once per cluster, to `/etc/pve/priv/authorized_keys` on any node.
That file is shared across the cluster (root's `authorized_keys` on every
node), so nodes added later get it automatically. The line is locked down:
`from="172.16.17.10"` (netbox001 only), `restrict` (no shell, PTY or
forwarding) and `command=` (the node runs only the inventory command, whatever
is requested). For BMC details `ipmitool` must be installed on each node
(`apt install ipmitool`); without it only serial and model are read.

Host keys are pinned on first contact in `~/.ssh/known_hosts_proxmox`. If a
node is rebuilt, remove its entry there. Nodes the key can't reach are a
warning; the rest of the sync still runs.

### Behaviour

- **Nodes are discovered from the Proxmox cluster membership** (`/cluster/status`).
  Each is matched to a NetBox device: in the cluster by name (or
  `proxmox_node_map`), else by name anywhere in NetBox if that device has no
  cluster (it is moved into this one). A same-named device in a *different*
  cluster is never moved; that is a warning.
- **Missing nodes are created**, named as in Proxmox, copying device type,
  role, site, location, platform and tenant from the host the sync connected
  through. Fix the device type afterwards if that node is different hardware;
  the sync never changes it again.
- A node device without a primary IP gets the node's **cluster IP** on the
  node interface that carries it (e.g. `vmbr0.20`), created on the device if
  needed. Every node then has a primary IP, so the API connection fails over
  to any node that is up.
- **Guests tagged `netbox-skip` in Proxmox are left out entirely**: never
  created, updated or deleted, and neither is a NetBox VM holding their VMID or
  a hand-made VM of the same name. Use it for guests modelled another way in
  NetBox, e.g. firewall VMs kept as NetBox *devices* so their interfaces, CARP
  groups and Oxidized backups stay hand-curated. Add the tag in Proxmox
  (guest > Summary > Tags); each run logs the guests it skipped.
- NetBox VMs in the cluster **without `proxmox_vmid` are deleted** (hand-made
  entries), as are VMs whose VMID no longer exists in Proxmox, with their
  interfaces, MACs and IPs. Deletes run before creates. A deleted hand-made
  VM's `zabbix_hostid` and tags carry over to a new VM of the same name, so
  netbox-zabbix-sync keeps tracking the host instead of logging "host already
  present".
- Interfaces, disks and IPs on synced VMs that Proxmox/the guest no longer
  reports are removed. A MAC or IP already assigned to some other NetBox object
  is never taken over; it's reported as a warning.
- **Guest IPs go into a VRF when NetBox says so**: if a prefix that contains the
  IP is in a VRF *and* has the NIC's Proxmox VLAN tag as its VLAN, the IP is
  created in (and matched against) that VRF; otherwise it stays in the global
  table. This lets hosted customer firewalls that all use the same LAN (e.g.
  `172.18.255.0/24`) each live in their own VRF: create the VRF, then the
  prefix in it with the customer's VLAN. Two VRFs matching is a warning and the
  IP stays global.
- Primary IPv4 prefers a private (RFC 1918) address, so LAN monitoring reaches
  it. Platform is only set when blank (from the guest OS).
- Stopped guests become **Offline** (netbox-zabbix-sync disables, not deletes,
  the Zabbix host).
- Safety stops: nothing is deleted if any Proxmox API listing failed, Proxmox
  returned no guests, or more than 20% of a cluster's VMID-matched VMs would go.
