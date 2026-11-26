#!/usr/bin/env python3
'''Sync Proxmox VE clusters into NetBox.

Which clusters, and how to reach them, is configured on the NetBox cluster
itself (custom fields, group "Proxmox sync"):

  proxmox_sync_enabled   include the cluster in runs
  proxmox_token_id       e.g. netbox@pve!sync
  proxmox_verify_tls     off for self-signed node certificates
  proxmox_node_map       optional "pve-node=NetBox-device,..." when names differ

The API endpoint is not configured: the sync tries the primary IP of each
device in the NetBox cluster (port 8006, active devices first) and uses the
first node that answers. Onboarding a cluster = create it in NetBox, add one of
its hosts to it with a primary IP, set the fields above.

The token secret is NOT stored in NetBox (custom fields are readable by every
NetBox user). It lives in this repo's .env as PVE_TOKEN_SECRET_<CLUSTER>, where
<CLUSTER> is the NetBox cluster name upper-cased with non-alphanumerics -> "_"
(DC1-Internal -> PVE_TOKEN_SECRET_DC1_INTERNAL). See README "Proxmox sync" for
the Proxmox user/role setup.

Proxmox is authoritative for each synced cluster's virtual machines:

- Nodes come from the Proxmox cluster membership. Each is matched to a NetBox
  device: in the cluster by name (or the node map), else by name anywhere in
  NetBox (that device is moved into the cluster). Nodes with no device are
  created, copying site, role, device type, platform and tenant from the host
  the sync connected through. A node device without a primary IP gets the
  node's cluster IP, on the matching interface (e.g. vmbr0), so the sync can
  reach the API through any node.
- Guests tagged SKIP_TAG ("netbox-skip") in Proxmox are left alone: never
  created, updated or deleted, nor is a NetBox VM holding their VMID or a
  hand-made VM of the same name. Use it for guests modelled another way in
  NetBox (e.g. firewalls kept as devices).
- VMs (QEMU and LXC; templates skipped) are matched on the proxmox_vmid custom
  field. Missing ones are created; all get status, host node, vCPUs, memory,
  SMBIOS UUID (serial), virtual disks, interfaces + MACs, guest-agent IPs and a
  primary IPv4 (a private address preferred). Platform is only set when blank,
  from the guest OS.
- NetBox VMs in the cluster without a proxmox_vmid (hand-made entries) are
  deleted, as are VMs whose VMID no longer exists in Proxmox. Deletes run
  before creates so their IPs/MACs are freed. A deleted hand-made VM's
  zabbix_hostid and tags carry over to a new VM of the same name, so
  netbox-zabbix-sync keeps tracking the host.
- Safety stops: nothing is deleted if any Proxmox API listing failed, Proxmox
  returned no guests, or more than MAX_DELETE_FRACTION of the cluster's
  VMID-matched VMs would be deleted.

Always run with --dry-run first: it prints every change and writes nothing.
'''
# System imports
import argparse
import ipaddress
import logging
import os
import re
import subprocess
import sys

# External imports
import dotenv
import pynetbox
import requests
import urllib3

logger = logging.getLogger(__name__)
LOGGING_FORMAT = '%(asctime)s %(levelname)s %(message)s'

MAX_DELETE_FRACTION = 0.2
CF_VMID = 'proxmox_vmid'
SKIP_TAG = 'netbox-skip'   # Proxmox guest tag: leave this guest out of the sync entirely
CF_ZABBIX = 'zabbix_hostid'
DISK_KEY_RE = re.compile(r'^(scsi|virtio|sata|ide)\d+$')
LXC_DISK_KEY_RE = re.compile(r'^(rootfs|mp\d+)$')
NET_KEY_RE = re.compile(r'^net\d+$')
# Guest OS id (QEMU agent get-osinfo "id") -> NetBox platform slug.
OS_PLATFORM = {'ubuntu': 'ubuntu', 'centos': 'centos', 'debian': 'linux', 'rhel': 'linux',
               'rocky': 'linux', 'almalinux': 'linux', 'fedora': 'linux'}
# Guest interfaces whose addresses are never synced.
SKIP_GUEST_IFACES = re.compile(r'^(lo|docker\d*|br-|veth|virbr|cni|flannel|cali|tailscale|wg)')
# Hardware inventory over SSH: a key in the cluster-wide /etc/pve/priv/authorized_keys,
# locked to INVENTORY_COMMAND (see --print-authorized-keys and the README).
SSH_KEY = os.path.expanduser(os.environ.get('PVE_SSH_KEY', '~/.ssh/netbox_pve_inventory'))
SSH_KNOWN_HOSTS = os.path.expanduser('~/.ssh/known_hosts_proxmox')
INVENTORY_COMMAND = ("for k in system-manufacturer system-product-name system-serial-number bios-version; "
                     "do printf '%s=' $k; /usr/sbin/dmidecode -s $k; done; "
                     "command -v ipmitool >/dev/null && ipmitool lan print 1 2>/dev/null; true")
CREATED_MARK = 'Created by sync_proxmox.py; device type copied from '
JUNK_SERIALS = {'', 'not specified', 'to be filled by o.e.m.', 'default string', 'none', '0123456789', 'system serial number'}
BMC_NAMES = {'dell': 'iDRAC', 'hpe': 'iLO', 'hp': 'iLO'}
PRIVATE_V4 = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]


class Plan:
    '''Counts and prints changes; callers skip writes when dry_run.'''

    def __init__(self, dry_run: bool, cluster: str):
        self.dry_run = dry_run
        self.cluster = cluster
        self.counts = {'create': 0, 'update': 0, 'delete': 0, 'warn': 0}

    def note(self, kind: str, msg: str):
        self.counts[kind] = self.counts.get(kind, 0) + 1
        prefix = 'DRY-RUN ' if self.dry_run and kind != 'warn' else ''
        (logger.warning if kind == 'warn' else logger.info)(f'[{self.cluster}] {prefix}{kind.upper():6} {msg}')


# --- Proxmox ---------------------------------------------------------------

PVE_PORT = 8006


class Proxmox:
    def __init__(self, url, token_id, secret, verify):
        self.base = url.rstrip('/') + '/api2/json'
        self.session = requests.Session()
        self.session.headers['Authorization'] = f'PVEAPIToken={token_id}={secret}'
        self.session.verify = verify
        self.errors = []
        self.forbidden = set()

    def get(self, path, required=True):
        try:
            resp = self.session.get(self.base + path, timeout=20)
            resp.raise_for_status()
            return resp.json().get('data')
        except (requests.RequestException, ValueError) as exc:
            status = getattr(getattr(exc, 'response', None), 'status_code', None)
            if status == 403:
                kind = re.sub(r'/nodes/[^/]+/', '/nodes/<node>/', re.sub(r'/\d+/', '/<id>/', path))
                if kind not in self.forbidden:
                    self.forbidden.add(kind)
                    logger.warning(f'Proxmox API {kind}: permission denied for this token '
                                   f'(guest-agent calls need VM.Monitor on Proxmox 8, VM.GuestAgent.Audit on 9)')
            if required:
                self.errors.append(f'{path}: {status or exc}')
                logger.error(f'Proxmox API {path} failed: {status or exc}')
            else:
                logger.debug(f'Proxmox API {path} unavailable: {status or exc}')
            return None


def guest_tags(res: dict) -> set:
    '''Proxmox guest tags (";"-separated in /cluster/resources), lower-cased.'''
    return {t for t in re.split(r'[;,\s]+', str(res.get('tags') or '').lower()) if t}


def size_to_mb(text: str) -> int:
    '''"40G" / "512M" / "2T" -> MB (binary, matching how existing NetBox VMs were entered).'''
    m = re.match(r'^(\d+(?:\.\d+)?)([KMGT]?)$', text or '')
    if not m:
        return 0
    value, unit = float(m.group(1)), m.group(2)
    return int(value * {'K': 1 / 1024, '': 1 / (1024 * 1024), 'M': 1, 'G': 1024, 'T': 1024 * 1024}[unit])


def parse_kv(text: str) -> dict:
    '''Proxmox "a=1,b=2" option strings; a bare first item is returned as "_".'''
    out = {}
    for i, part in enumerate((text or '').split(',')):
        if '=' in part:
            k, v = part.split('=', 1)
            out[k.strip()] = v.strip()
        elif i == 0:
            out['_'] = part.strip()
    return out


def collect_vm(pve: Proxmox, res: dict) -> dict:
    '''Everything NetBox needs about one guest.'''
    node, vmid, kind = res['node'], res['vmid'], res['type']
    cfg = pve.get(f'/nodes/{node}/{kind}/{vmid}/config') or {}
    vm = {
        'vmid': vmid, 'kind': kind, 'node': node, 'name': res.get('name') or f'vm{vmid}',
        'status': 'active' if res.get('status') == 'running' else 'offline',
        'running': res.get('status') == 'running',
        'memory': int(cfg.get('memory') or (res.get('maxmem', 0) // (1024 * 1024)) or 0) or None,
        'uuid': '', 'disks': [], 'nics': [], 'ips_known': False, 'ostype': None,
    }
    if kind == 'qemu':
        vm['vcpus'] = int(cfg.get('vcpus') or int(cfg.get('sockets', 1)) * int(cfg.get('cores', 1)))
        vm['uuid'] = parse_kv(cfg.get('smbios1')).get('uuid', '').lower()
        for key, val in cfg.items():
            if DISK_KEY_RE.match(key):
                opts = parse_kv(val)
                if opts.get('media') == 'cdrom' or 'size' not in opts:
                    continue
                vm['disks'].append((key, size_to_mb(opts['size'])))
            elif NET_KEY_RE.match(key):
                opts = parse_kv(val)
                mac = next((v for k, v in opts.items() if k in ('virtio', 'e1000', 'e1000e', 'vmxnet3', 'rtl8139')), None)
                vm['nics'].append({'key': key, 'mac': (mac or '').upper(), 'bridge': opts.get('bridge', ''),
                                   'tag': opts.get('tag', ''), 'name': key, 'ips': []})
    else:  # lxc
        vm['vcpus'] = int(cfg.get('cores') or res.get('maxcpu') or 1)
        for key, val in cfg.items():
            if LXC_DISK_KEY_RE.match(key):
                opts = parse_kv(val)
                if 'size' in opts:
                    vm['disks'].append((key, size_to_mb(opts['size'])))
            elif NET_KEY_RE.match(key):
                opts = parse_kv(val)
                vm['nics'].append({'key': key, 'mac': opts.get('hwaddr', '').upper(), 'bridge': opts.get('bridge', ''),
                                   'tag': opts.get('tag', ''), 'name': opts.get('name') or key, 'ips': []})
    vm['disks'].sort()
    vm['nics'].sort(key=lambda n: int(n['key'][3:]))
    if vm['running']:
        fill_guest_ips(pve, vm, cfg)
    return vm


def _add_ip(nic, addr, plen):
    try:
        iface = ipaddress.ip_interface(f'{addr}/{plen}')
    except ValueError:
        return
    if iface.ip.is_loopback or iface.ip.is_link_local or iface.ip.is_multicast:
        return
    nic['ips'].append(str(iface))


def fill_guest_ips(pve: Proxmox, vm: dict, cfg: dict):
    '''Guest IPs per NIC (matched by MAC) and guest OS, when the guest reports them.'''
    by_mac = {n['mac']: n for n in vm['nics'] if n['mac']}
    if vm['kind'] == 'qemu':
        agent = parse_kv(str(cfg.get('agent', '0')))
        if agent.get('enabled', agent.get('_', '0')) != '1':
            return
        data = pve.get(f"/nodes/{vm['node']}/qemu/{vm['vmid']}/agent/network-get-interfaces", required=False)
        osinfo = pve.get(f"/nodes/{vm['node']}/qemu/{vm['vmid']}/agent/get-osinfo", required=False)
        if osinfo:
            vm['ostype'] = (osinfo.get('result') or {}).get('id')
        result = data.get('result') if isinstance(data, dict) else None
        if not isinstance(result, list):   # agent not answering / error object: leave the guest's IPs alone
            if data:
                logger.debug(f"vm {vm['vmid']}: unexpected guest-agent reply {str(data)[:200]}")
            return
        vm['ips_known'] = True
        for gi in result:
            if not isinstance(gi, dict):
                continue
            name, mac = gi.get('name', ''), (gi.get('hardware-address') or '').upper()
            nic = by_mac.get(mac)
            if nic is None or SKIP_GUEST_IFACES.match(name):
                continue
            nic['name'] = name
            for a in gi.get('ip-addresses') or []:
                _add_ip(nic, a.get('ip-address'), a.get('prefix'))
    else:
        data = pve.get(f"/nodes/{vm['node']}/lxc/{vm['vmid']}/interfaces", required=False)
        if not isinstance(data, list):
            return
        vm['ips_known'] = True
        for gi in data:
            if not isinstance(gi, dict):
                continue
            nic = by_mac.get((gi.get('hwaddr') or '').upper())
            if nic is None:
                continue
            for key in ('inet', 'inet6'):
                for cidr in (gi.get(key) or '').split():
                    if '/' in cidr:
                        _add_ip(nic, *cidr.split('/', 1))


def choose_primary(vm: dict):
    '''First private IPv4 (so LAN monitoring like Zabbix reaches it), else first IPv4.'''
    v4 = [a for n in vm['nics'] for a in n['ips'] if ipaddress.ip_interface(a).version == 4]
    private = [a for a in v4 if any(ipaddress.ip_interface(a).ip in net for net in PRIVATE_V4)]
    return (private or v4 or [None])[0]


# --- NetBox ------------------------------------------------------------------

class ClusterSync:
    def __init__(self, nb, cluster, pve, plan, seed):
        self.nb, self.cluster, self.pve, self.plan, self.seed = nb, cluster, pve, plan, seed
        self.deleted_vm_ids = set()   # VMs deleted (or, in dry run, to be deleted) this run
        self.carry = {}               # lower(new name) -> {'zabbix_hostid', 'tags', 'ips', 'primary4', 'primary6', 'from'}
        self.carry_map = {}           # lower(old hand-made name) -> lower(Proxmox name), from --carry-map
        self._vrf_cache = {}          # (network, vlan tag) -> NetBox VRF or None

    def vrf_for(self, addr, tag):
        '''VRF for a guest IP: the one prefix containing it that is in a VRF and carries the NIC's VLAN.

        Lets overlapping customer LANs (e.g. every hosted firewall on 172.18.255.0/24) live in their own VRF;
        anything without such a prefix stays in the global table.'''
        if not tag:
            return None
        net = str(ipaddress.ip_interface(addr).network)
        key = (net, str(tag))
        if key not in self._vrf_cache:
            found = {p.vrf.id: p.vrf for p in self.nb.ipam.prefixes.filter(contains=str(ipaddress.ip_interface(addr).ip))
                     if p.vrf and p.vlan and str(p.vlan.vid) == str(tag)}
            if len(found) > 1:
                self.plan.note('warn', f"{addr} on VLAN {tag}: prefixes in {len(found)} VRFs "
                                       f"({', '.join(v.name for v in found.values())}) match; using global")
            self._vrf_cache[key] = next(iter(found.values())) if len(found) == 1 else None
        return self._vrf_cache[key]

    def _ip_label(self, addr, tag):
        vrf = self.vrf_for(addr, tag)
        return f'{addr} (VRF {vrf.name})' if vrf else addr

    # -- helpers that treat things on to-be-deleted VMs as free (accurate dry runs)
    def _on_deleted_vm(self, obj) -> bool:
        ao = getattr(obj, 'assigned_object', None)
        vm = getattr(ao, 'virtual_machine', None) if ao else None
        return vm is not None and vm.id in self.deleted_vm_ids

    def ensure_nodes(self, pve_nodes, node_map):
        """NetBox device per Proxmox node (matched, moved into the cluster, or created)."""
        in_cluster = list(self.nb.dcim.devices.filter(cluster_id=self.cluster.id))
        out = {}
        for node in pve_nodes:
            name = node['name']
            want = node_map.get(name)
            if want:
                cands = [d for d in in_cluster if d.name == want] or list(self.nb.dcim.devices.filter(name=want))
            else:
                cands = [d for d in in_cluster if d.name.lower() == name.lower()] or \
                    [d for d in in_cluster if d.name.lower().endswith(name.lower())] or \
                    [d for d in self.nb.dcim.devices.filter(name__ie=name)]
            if len(cands) > 1:
                self.plan.note('warn', f'node {name}: {len(cands)} NetBox devices match '
                                       f'({", ".join(d.name for d in cands)}); its VMs get no host device. '
                                       f'Set proxmox_node_map on the cluster or remove the duplicate.')
                out[name] = None
                continue
            dev = cands[0] if cands else None
            if dev is None:
                dev = self.create_node(name)
            elif dev.cluster and dev.cluster.id != self.cluster.id:
                self.plan.note('warn', f'node {name}: device {dev.name} belongs to cluster {dev.cluster.name}; '
                                       f'not moved, its VMs get no host device. Fix in NetBox or set proxmox_node_map.')
                out[name] = None
                continue
            elif not dev.cluster:
                self.plan.note('update', f'node {name}: device {dev.name} -> cluster {self.cluster.name}')
                if not self.plan.dry_run:
                    dev.update({'cluster': self.cluster.id})
            else:
                logger.info(f'[{self.cluster.name}] MATCH  node {name} -> device {dev.id} {dev.name}')
            out[name] = dev
            self.ensure_node_ip(name, dev, node.get('ip'))
            self.sync_hardware(name, dev, node.get('ip'))
        return out

    def create_node(self, name):
        s = self.seed
        fields = {'name': name, 'device_type': s.device_type.id, 'role': s.role.id, 'site': s.site.id,
                  'cluster': self.cluster.id, 'status': 'active',
                  'description': f'{CREATED_MARK}{s.name} (unverified)'}
        for attr in ('platform', 'tenant', 'location'):
            if getattr(s, attr, None):
                fields[attr] = getattr(s, attr).id
        self.plan.note('create', f'node device {name} (copied from {s.name}: {s.device_type.model}, '
                                 f'role {s.role.name}, site {s.site.name})')
        if self.plan.dry_run:
            return None
        return self.nb.dcim.devices.create(**fields)

    def ensure_node_ip(self, node, dev, ip):
        """Give a node device without a primary IP its Proxmox cluster IP."""
        if not ip or (dev is not None and (dev.primary_ip4 or dev.primary_ip6)):
            return
        net = self.pve.get(f'/nodes/{node}/network', required=False) or []
        hit = next((i for i in net if ip in (i.get('address'), i.get('address6'))
                    or str(i.get('cidr', '')).split('/')[0] == ip), None)
        if hit is None:
            self.plan.note('warn', f'node {node}: cluster IP {ip} not found on any node interface; primary IP not set')
            return
        cidr = hit.get('cidr') if str(hit.get('cidr', '')).startswith(ip + '/') else hit.get('cidr6') or f'{ip}/32'
        iface_name = hit['iface']
        iface_type = {'bridge': 'bridge', 'bond': 'lag', 'vlan': 'virtual', 'OVSBridge': 'bridge'}.get(hit.get('type'), 'other')
        label = f'node {node}'
        same = list(self.nb.ipam.ip_addresses.filter(address=cidr))
        taken = [a for a in same if a.assigned_object_id and
                 getattr(getattr(a.assigned_object, 'device', None), 'id', None) != getattr(dev, 'id', None)]
        if taken:
            owner = getattr(taken[0].assigned_object, 'device', None) or \
                getattr(taken[0].assigned_object, 'virtual_machine', None)
            self.plan.note('warn', f'{label}: {cidr} is already assigned to {owner} / {taken[0].assigned_object}; '
                                   f'primary IP not set')
            return
        self.plan.note('update', f'{label}: primary IPv4 -> {cidr} on {iface_name}')
        if self.plan.dry_run or dev is None:
            return
        iface = self.nb.dcim.interfaces.get(device_id=dev.id, name=iface_name) or \
            self.nb.dcim.interfaces.create(device=dev.id, name=iface_name, type=iface_type,
                                           description='Proxmox cluster IP (sync_proxmox.py)')
        ipobj = same[0] if same else None
        if ipobj is None:
            ipobj = self.nb.ipam.ip_addresses.create(address=cidr, status='active',
                                                     assigned_object_type='dcim.interface', assigned_object_id=iface.id)
        elif ipobj.assigned_object_id != iface.id:
            ipobj.update({'assigned_object_type': 'dcim.interface', 'assigned_object_id': iface.id})
        dev.update({'primary_ip4' if ':' not in ip else 'primary_ip6': ipobj.id})

    # -- hardware inventory (dmidecode / ipmitool over the locked-down SSH key)
    def read_inventory(self, ip):
        cmd = ['ssh', '-i', SSH_KEY, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'IdentitiesOnly=yes',
               '-o', f'UserKnownHostsFile={SSH_KNOWN_HOSTS}', '-o', 'StrictHostKeyChecking=accept-new',
               f'root@{ip}', 'inventory']
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=40, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, type(exc).__name__
        if p.returncode != 0:
            return None, (p.stderr.strip().splitlines() or [f'exit {p.returncode}'])[-1]
        inv = {}
        for line in p.stdout.splitlines():
            if '=' in line and ':' not in line.split('=', 1)[0]:
                k, v = line.split('=', 1)
                inv[k.strip()] = v.strip()
            elif ':' in line:
                k, v = line.split(':', 1)
                inv['ipmi ' + k.strip().lower()] = v.strip()
        return inv, None

    @staticmethod
    def inventory_targets(dev, ip):
        '''SSH targets for a node: its Proxmox cluster IP, then its NetBox primary IP(s).

        The cluster IP is often on a corosync-only network the sync host cannot
        reach, while the primary IP is the management address used for the API.'''
        out = [ip] if ip else []
        for attr in ('primary_ip4', 'primary_ip6'):
            obj = getattr(dev, attr, None) if dev is not None else None
            if obj:
                addr = str(ipaddress.ip_interface(str(obj.address)).ip)
                if addr not in out:
                    out.append(addr)
        return out

    def sync_hardware(self, node, dev, ip):
        targets = self.inventory_targets(dev, ip)
        if not targets or not os.path.exists(SSH_KEY):
            return
        label = f'node {node}'
        inv, errs = None, []
        for target in targets:
            inv, err = self.read_inventory(target)
            if inv is not None:
                if target != ip:
                    logger.debug(f'[{self.cluster.name}] {label}: inventory read via primary IP {target}')
                break
            errs.append(f'{target}: {err}')
        if inv is None:
            self.plan.note('warn', f'{label}: hardware inventory unavailable over SSH ({"; ".join(errs)}); '
                                   f'see README "Hardware inventory"')
            return
        if dev is None:       # created in a dry run
            logger.info(f"[{self.cluster.name}] {label}: hardware {inv.get('system-manufacturer')} "
                        f"{inv.get('system-product-name')} serial {inv.get('system-serial-number')}")
            return
        serial = inv.get('system-serial-number', '')
        if serial.lower() not in JUNK_SERIALS and dev.serial != serial:
            self.plan.note('update', f'{label}: serial {dev.serial or None!r} -> {serial!r}')
            if not self.plan.dry_run:
                dev.update({'serial': serial})
        self.sync_device_type(label, dev, inv.get('system-manufacturer', ''), inv.get('system-product-name', ''))
        self.sync_bmc(label, dev, inv)

    def sync_device_type(self, label, dev, mfr, model):
        if not model or model.lower() in JUNK_SERIALS:
            return
        cur = dev.device_type
        marked = (dev.description or '').startswith(CREATED_MARK)
        if cur.model.lower() == model.lower():
            if marked:
                self.plan.note('update', f'{label}: device type {cur.model} confirmed by hardware')
                if not self.plan.dry_run:
                    dev.update({'description': ''})
            return
        mfr_key = (mfr.split() or [''])[0].lower()
        types = [t for t in self.nb.dcim.device_types.filter(q=model)
                 if model.lower() in (t.model.lower(), (t.part_number or '').lower())
                 and (not mfr_key or t.manufacturer.name.lower().startswith(mfr_key)
                      or t.manufacturer.slug.startswith(mfr_key))]
        fixable = marked or cur.model.lower().startswith('generic')
        if len(types) == 1 and fixable:
            self.plan.note('update', f'{label}: device type {cur.manufacturer.name} {cur.model} -> '
                                     f'{types[0].manufacturer.name} {types[0].model} (from hardware)')
            if not self.plan.dry_run:
                changes = {'device_type': types[0].id}
                if marked:
                    changes['description'] = ''
                dev.update(changes)
        elif not types:
            self.plan.note('warn', f'{label}: hardware is {mfr} {model}, NetBox has {cur.model}; no device type '
                                   f'"{model}" in NetBox (import it from the devicetype-library)')
        elif fixable:
            self.plan.note('warn', f'{label}: hardware is {mfr} {model}; {len(types)} matching NetBox device types, not changed')
        else:
            self.plan.note('warn', f'{label}: hardware is {mfr} {model} but NetBox says {cur.model}; not changed '
                                   f'(only placeholders and sync-created nodes are corrected)')

    def sync_bmc(self, label, dev, inv):
        addr, mask, mac = inv.get('ipmi ip address'), inv.get('ipmi subnet mask'), inv.get('ipmi mac address', '')
        if not addr or addr == '0.0.0.0':
            return
        try:
            cidr = str(ipaddress.ip_interface(f'{addr}/{mask or "32"}'))
        except ValueError:
            return
        mfr_key = (inv.get('system-manufacturer', '').split() or [''])[0].lower()
        bmc_name = BMC_NAMES.get(mfr_key, 'BMC')
        ifaces = list(self.nb.dcim.interfaces.filter(device_id=dev.id))
        iface = next((i for i in ifaces if i.name.lower() in ('idrac', 'ilo', 'ipmi', 'bmc')), None)
        if iface is None:
            self.plan.note('create', f'{label}: interface {bmc_name} (mgmt only) for the BMC')
            if self.plan.dry_run:
                return
            iface = self.nb.dcim.interfaces.create(device=dev.id, name=bmc_name, type='1000base-t', mgmt_only=True)
        mac = mac.upper()
        cur_mac = getattr(iface, 'primary_mac_address', None)
        if mac and not (cur_mac and str(cur_mac.mac_address).upper() == mac):
            found = list(self.nb.dcim.mac_addresses.filter(mac_address=mac))
            other = [f for f in found if f.assigned_object_id and f.assigned_object_id != iface.id]
            if other:
                self.plan.note('warn', f'{label}: BMC MAC {mac} is assigned to {other[0].assigned_object}; skipped')
            else:
                self.plan.note('update', f'{label}: {iface.name} MAC -> {mac}')
                if not self.plan.dry_run:
                    if found:
                        macobj = found[0]
                        macobj.update({'assigned_object_type': 'dcim.interface', 'assigned_object_id': iface.id})
                    else:
                        macobj = self.nb.dcim.mac_addresses.create(
                            mac_address=mac, assigned_object_type='dcim.interface', assigned_object_id=iface.id)
                    iface.update({'primary_mac_address': macobj.id})
        cur_oob = str(dev.oob_ip.address) if getattr(dev, 'oob_ip', None) else None
        if cur_oob == cidr:
            return
        same = list(self.nb.ipam.ip_addresses.filter(address=cidr))
        taken = [a for a in same if a.assigned_object_id and a.assigned_object_id != iface.id]
        if taken:
            self.plan.note('warn', f'{label}: BMC IP {cidr} is assigned to {taken[0].assigned_object}; oob IP not set')
            return
        self.plan.note('update', f'{label}: out-of-band IP {cur_oob} -> {cidr} on {iface.name}')
        if self.plan.dry_run:
            return
        if same:
            ipobj = same[0]
            ipobj.update({'assigned_object_type': 'dcim.interface', 'assigned_object_id': iface.id})
        else:
            ipobj = self.nb.ipam.ip_addresses.create(address=cidr, status='active',
                                                     assigned_object_type='dcim.interface', assigned_object_id=iface.id)
        dev.update({'oob_ip': ipobj.id})

    def delete_vm(self, v, reason):
        cf = v.custom_fields or {}
        ips = []
        if not cf.get(CF_VMID):
            # Hand-made entry: keep its IPs (detached) for the matching new VM.
            ips = list(self.nb.ipam.ip_addresses.filter(virtual_machine_id=v.id))
            key = self.carry_map.get(v.name.lower(), v.name.lower())
            self.carry[key] = {'zabbix_hostid': cf.get(CF_ZABBIX), 'tags': [t.id for t in v.tags],
                               'ips': [(ip.id, str(ip.address)) for ip in ips],
                               'primary4': v.primary_ip4.id if v.primary_ip4 else None,
                               'primary6': v.primary_ip6.id if v.primary_ip6 else None, 'from': v.name}
        keep = f'; keeping {len(ips)} IP(s) for the new VM' if ips else ''
        self.plan.note('delete', f'vm {v.name} (NetBox {v.id}): {reason}{keep}')
        self.deleted_vm_ids.add(v.id)
        if not self.plan.dry_run:
            if ips:
                if v.primary_ip4 or v.primary_ip6:
                    v.update({'primary_ip4': None, 'primary_ip6': None})
                for ip in ips:
                    ip.update({'assigned_object_type': None, 'assigned_object_id': None})
            v.delete()

    def apply_carried_ips(self, label, vm, nb_vm, carried):
        '''Put a deleted hand-made VM's IPs on its successor (first NIC); returns the carried primary IPv4 address.'''
        carried['used'] = True
        reported = {a for n in vm['nics'] for a in n['ips']}
        todo = [(i, a) for i, a in carried['ips'] if a not in reported]   # reported ones are re-attached by sync_ips
        primary = next((a for i, a in carried['ips'] if i == carried['primary4']), None)
        if not todo:
            return primary
        nic = vm['nics'][0]['name'] if vm['nics'] else None
        if nic is None:
            self.plan.note('warn', f"{label}: no NIC to carry IPs {', '.join(a for _, a in todo)} from {carried['from']}; left unassigned")
            return None
        self.plan.note('update', f"{label}: carry IP(s) {', '.join(a for _, a in todo)} from {carried['from']} to {nic}")
        if nb_vm is not None and not self.plan.dry_run:
            iface = self.nb.virtualization.interfaces.get(virtual_machine_id=nb_vm.id, name=nic)
            for ip_id, _addr in todo:
                self.nb.ipam.ip_addresses.get(ip_id).update(
                    {'assigned_object_type': 'virtualization.vminterface', 'assigned_object_id': iface.id})
        return primary

    def sync_vm(self, vm, nb_vm, node_dev, platforms):
        label = f"vm {vm['name']} (vmid {vm['vmid']})"
        want = {'name': vm['name'], 'status': vm['status'], 'vcpus': vm['vcpus'], 'memory': vm['memory'],
                'device': node_dev.id if node_dev else None, 'serial': vm['uuid'] or ''}
        if nb_vm is None:
            carried = self.carry.get(vm['name'].lower(), {})
            if carried:
                extra_from = f" (replaces hand-made {carried['from']})"
            else:
                extra_from = ''
            cfs = {CF_VMID: vm['vmid']}
            if carried.get('zabbix_hostid'):
                cfs[CF_ZABBIX] = carried['zabbix_hostid']
            extra = extra_from + (f" (carrying zabbix_hostid {carried['zabbix_hostid']})" if carried.get('zabbix_hostid') else '')
            self.plan.note('create', f"{label} on {vm['node']}: "
                                     f"{ {k: v for k, v in want.items() if k != 'name'} }{extra}")
            if not self.plan.dry_run:
                nb_vm = self.nb.virtualization.virtual_machines.create(
                    cluster=self.cluster.id, custom_fields=cfs, tags=carried.get('tags', []),
                    **{k: v for k, v in want.items() if v is not None})
        else:
            cur = {'name': nb_vm.name, 'status': nb_vm.status.value if nb_vm.status else None,
                   'vcpus': int(nb_vm.vcpus) if nb_vm.vcpus is not None else None,
                   'memory': nb_vm.memory, 'device': nb_vm.device.id if nb_vm.device else None,
                   'serial': (nb_vm.serial or '').lower()}
            changes = {k: v for k, v in want.items() if v is not None and cur.get(k) != v}
            if changes:
                self.plan.note('update', f'{label}: ' + ', '.join(f'{k} {cur.get(k)!r} -> {v!r}' for k, v in changes.items()))
                if not self.plan.dry_run:
                    nb_vm.update(changes)
        slug = OS_PLATFORM.get((vm['ostype'] or '').lower())
        if slug and slug in platforms and (nb_vm is None or nb_vm.platform is None):
            self.plan.note('update', f"{label}: platform -> {platforms[slug].name} (guest OS {vm['ostype']})")
            if nb_vm is not None and not self.plan.dry_run:
                nb_vm.update({'platform': platforms[slug].id})

        self.sync_disks(label, vm, nb_vm)
        self.sync_interfaces(label, vm, nb_vm)
        carried = self.carry.get(vm['name'].lower())
        carried_primary = self.apply_carried_ips(label, vm, nb_vm, carried) \
            if carried and carried.get('ips') and not carried.get('used') else None
        primary = choose_primary(vm) or carried_primary
        cur_primary = str(nb_vm.primary_ip4.address) if nb_vm is not None and nb_vm.primary_ip4 else None
        if primary and cur_primary != primary and (cur_primary is None or vm['ips_known']):
            self.plan.note('update', f'{label}: primary IPv4 {cur_primary} -> {primary}')
            if nb_vm is not None and not self.plan.dry_run:
                ips = list(self.nb.ipam.ip_addresses.filter(address=primary, virtual_machine_id=nb_vm.id))
                if len(ips) == 1:
                    nb_vm.update({'primary_ip4': ips[0].id})

    def sync_disks(self, label, vm, nb_vm):
        existing = {d.name: d for d in self.nb.virtualization.virtual_disks.filter(virtual_machine_id=nb_vm.id)} if nb_vm else {}
        for name, size in vm['disks']:
            d = existing.pop(name, None)
            if d is None:
                self.plan.note('create', f'{label}: disk {name} {size} MB')
                if nb_vm is not None and not self.plan.dry_run:
                    self.nb.virtualization.virtual_disks.create(virtual_machine=nb_vm.id, name=name, size=size)
            elif d.size != size:
                self.plan.note('update', f'{label}: disk {name} {d.size} -> {size} MB')
                if not self.plan.dry_run:
                    d.update({'size': size})
        for name, d in existing.items():
            self.plan.note('delete', f'{label}: disk {name} (not in Proxmox)')
            if not self.plan.dry_run:
                d.delete()

    def sync_interfaces(self, label, vm, nb_vm):
        existing = list(self.nb.virtualization.interfaces.filter(virtual_machine_id=nb_vm.id)) if nb_vm else []
        by_mac = {}
        for iface in existing:
            mac = getattr(iface, 'primary_mac_address', None)
            if mac:
                by_mac[str(mac.mac_address).upper()] = iface
        by_name = {i.name: i for i in existing}
        seen = set()
        for nic in vm['nics']:
            desc = f"Proxmox {nic['key']} on {nic['bridge']}" + (f" VLAN {nic['tag']}" if nic['tag'] else '')
            iface = by_mac.get(nic['mac']) or by_name.get(nic['name'])
            if iface is None:
                self.plan.note('create', f"{label}: interface {nic['name']} {nic['mac']} ({desc})"
                                         + (f" IPs {', '.join(self._ip_label(a, nic['tag']) for a in nic['ips'])}"
                                            if nic['ips'] else ''))
                if nb_vm is not None and not self.plan.dry_run:
                    iface = self.nb.virtualization.interfaces.create(virtual_machine=nb_vm.id, name=nic['name'],
                                                                     description=desc)
            else:
                changes = {}
                if iface.name != nic['name']:
                    changes['name'] = nic['name']
                if (iface.description or '') != desc:
                    changes['description'] = desc
                if changes:
                    self.plan.note('update', f'{label}: interface {iface.name}: {changes}')
                    if not self.plan.dry_run:
                        iface.update(changes)
            if iface is not None:
                seen.add(iface.id)
            self.sync_mac(label, iface, nic['mac'])
            if vm['ips_known']:
                self.sync_ips(label, iface, nic)
        for iface in existing:
            if iface.id not in seen:
                self.plan.note('delete', f'{label}: interface {iface.name} (no matching Proxmox NIC)')
                if not self.plan.dry_run:
                    iface.delete()

    def sync_mac(self, label, iface, mac):
        if not mac:
            return
        if iface is not None:
            cur = getattr(iface, 'primary_mac_address', None)
            if cur and str(cur.mac_address).upper() == mac:
                return
        found_all = [f for f in self.nb.dcim.mac_addresses.filter(mac_address=mac) if not self._on_deleted_vm(f)]
        elsewhere = [f for f in found_all if f.assigned_object_id and (iface is None or f.assigned_object_id != iface.id)]
        if elsewhere:
            self.plan.note('warn', f'{label}: MAC {mac} is assigned to {elsewhere[0].assigned_object} in NetBox; skipped')
            return
        if iface is None:   # new interface in a dry run: already reported with the create
            return
        self.plan.note('update', f'{label}: interface {iface.name} MAC -> {mac}')
        if self.plan.dry_run:
            return
        found = found_all[0] if found_all else None
        if found is None:
            found = self.nb.dcim.mac_addresses.create(mac_address=mac, assigned_object_type='virtualization.vminterface',
                                                      assigned_object_id=iface.id)
        else:
            found.update({'assigned_object_type': 'virtualization.vminterface', 'assigned_object_id': iface.id})
        iface.update({'primary_mac_address': found.id})

    def sync_ips(self, label, iface, nic):
        current = {str(ip.address): ip for ip in self.nb.ipam.ip_addresses.filter(vminterface_id=iface.id)} if iface else {}
        for addr in nic['ips']:
            if addr in current:
                current.pop(addr)
                continue
            vrf = self.vrf_for(addr, nic['tag'])
            shown = self._ip_label(addr, nic['tag'])
            same = [ip for ip in self.nb.ipam.ip_addresses.filter(address=addr, vrf_id=vrf.id if vrf else 'null')
                    if not self._on_deleted_vm(ip)]
            assigned = [ip for ip in same if ip.assigned_object_id]
            if assigned:
                self.plan.note('warn', f'{label}: {shown} already exists in NetBox on {assigned[0].assigned_object}; '
                                       f'not reassigned')
                continue
            if len(same) > 1:
                self.plan.note('warn', f'{label}: {shown} exists {len(same)} times (unassigned) in NetBox; not assigned')
                continue
            if iface is None:   # new interface in a dry run: already listed with the create
                continue
            self.plan.note('create', f"{label}: IP {shown} on {nic['name']}")
            if not self.plan.dry_run:
                if same:
                    same[0].update({'assigned_object_type': 'virtualization.vminterface', 'assigned_object_id': iface.id})
                else:
                    self.nb.ipam.ip_addresses.create(address=addr, status='active', vrf=vrf.id if vrf else None,
                                                     assigned_object_type='virtualization.vminterface',
                                                     assigned_object_id=iface.id)
        for addr, ip in current.items():
            self.plan.note('delete', f"{label}: IP {addr} on {iface.name} (guest no longer reports it)")
            if not self.plan.dry_run:
                ip.delete()

    def run(self, node_map):
        version = self.pve.get('/version') or {}
        status = self.pve.get('/cluster/status') or []
        resources = self.pve.get('/cluster/resources?type=vm')
        if resources is None:
            logger.error(f'[{self.cluster.name}] could not list Proxmox guests; nothing changed')
            return False
        pve_name = next((s.get('name') for s in status if s.get('type') == 'cluster'), '(standalone)')
        nodes = sorted((s for s in status if s.get('type') == 'node'), key=lambda n: n['name'])
        all_guests = sorted((r for r in resources if not r.get('template')), key=lambda r: r['vmid'])
        skipped = [g for g in all_guests if SKIP_TAG in guest_tags(g)]
        guests = [g for g in all_guests if g not in skipped]
        for g in skipped:
            logger.info(f"[{self.cluster.name}] skipping {g.get('name')} (vmid {g['vmid']}): tagged {SKIP_TAG}")
        logger.info(f"[{self.cluster.name}] Proxmox {version.get('version', '?')} cluster {pve_name}: "
                    f"{len(nodes)} nodes, {len(all_guests)} guests ({len(skipped)} tagged {SKIP_TAG})")
        node_devs = self.ensure_nodes(nodes, node_map)
        platforms = {p.slug: p for p in self.nb.dcim.platforms.all()}

        nb_vms = list(self.nb.virtualization.virtual_machines.filter(cluster_id=self.cluster.id))
        by_vmid, unmanaged = {}, []
        for v in nb_vms:
            vmid = (v.custom_fields or {}).get(CF_VMID)
            if vmid is None:
                unmanaged.append(v)
            elif vmid in by_vmid:
                self.plan.note('warn', f'NetBox VMs {by_vmid[vmid].name} and {v.name} share VMID {vmid}; '
                                       f'{v.name} will be deleted')
                unmanaged.append(v)
            else:
                by_vmid[vmid] = v
        # Skipped guests still count as present, so a NetBox VM holding their VMID is not "gone".
        pve_vmids = {g['vmid'] for g in all_guests}
        gone = [v for vmid, v in by_vmid.items() if vmid not in pve_vmids]
        skip_names = {str(g.get('name', '')).lower() for g in skipped}
        unmanaged = [v for v in unmanaged if v.name.lower() not in skip_names]

        # Deletes first, so their IPs/MACs are free for the creates below.
        blockers = []
        if self.pve.errors:
            blockers.append(f'{len(self.pve.errors)} Proxmox API error(s)')
        if not all_guests:
            blockers.append('Proxmox returned no guests')
        if len(gone) > MAX_DELETE_FRACTION * max(len(by_vmid), 1) and len(gone) > 1:
            blockers.append(f'{len(gone)} of {len(by_vmid)} VMID-matched VMs would be deleted (> {MAX_DELETE_FRACTION:.0%})')
        for v in unmanaged + gone:
            if blockers:
                self.plan.note('warn', f'vm {v.name} (NetBox {v.id}) NOT deleted: {"; ".join(blockers)}')
            else:
                self.delete_vm(v, 'no proxmox_vmid (hand-made entry)' if v in unmanaged else 'VMID no longer in Proxmox')

        for res in guests:
            vm = collect_vm(self.pve, res)
            self.sync_vm(vm, by_vmid.get(res['vmid']), node_devs.get(vm['node']), platforms)
        for key, c in self.carry.items():
            if c.get('ips') and not c.get('used'):
                self.plan.note('warn', f"hand-made VM {c['from']}: no Proxmox guest named {key}; its IP(s) "
                                       f"{', '.join(a for _, a in c['ips'])} are left unassigned in NetBox")
        return not self.pve.errors


def connect(nb, cluster, token_id, secret, verify):
    '''Proxmox client for the first cluster node (by NetBox primary IP) whose API answers.'''
    devices = sorted(nb.dcim.devices.filter(cluster_id=cluster.id),
                     key=lambda d: (d.status.value != 'active', d.name))
    tried = []
    for dev in devices:
        ip = dev.primary_ip4 or dev.primary_ip6 or dev.primary_ip
        if not ip:
            continue
        addr = str(ipaddress.ip_interface(str(ip.address)).ip)
        host = f'[{addr}]' if ':' in addr else addr
        pve = Proxmox(f'https://{host}:{PVE_PORT}', token_id, secret, verify)
        try:
            resp = pve.session.get(pve.base + '/version', timeout=8)
        except requests.RequestException as exc:
            tried.append(f'{dev.name} {addr}: {type(exc).__name__}')
            continue
        if resp.status_code == 200:
            logger.info(f'[{cluster.name}] using Proxmox API on {dev.name} ({addr})')
            return pve, dev
        tried.append(f'{dev.name} {addr}: HTTP {resp.status_code}')
    if not tried:
        logger.error(f'[{cluster.name}] no device in the cluster has a primary IP to reach the Proxmox API')
    else:
        logger.error(f'[{cluster.name}] no Proxmox API reachable: ' + '; '.join(tried))
    return None, None


def env_secret_name(cluster_name: str) -> str:
    return 'PVE_TOKEN_SECRET_' + re.sub(r'[^A-Z0-9]+', '_', cluster_name.upper()).strip('_')


def main():
    parser = argparse.ArgumentParser(description='Sync Proxmox VE clusters into NetBox')
    parser.add_argument('--dry-run', action='store_true', help='Print changes, write nothing')
    parser.add_argument('-c', '--cluster', action='append', default=[],
                        help='Only this NetBox cluster (repeatable); default: all with proxmox_sync_enabled')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('--carry-map', default='',
                        help='old=new,... : hand-made NetBox VM names whose Proxmox guest has a different name '
                             '(their IPs, zabbix_hostid and tags move to it)')
    parser.add_argument('--print-authorized-keys', metavar='SOURCE_IP',
                        help="Print the line to add to a cluster's /etc/pve/priv/authorized_keys and exit")
    args = parser.parse_args()
    if args.print_authorized_keys:
        with open(SSH_KEY + '.pub', encoding='utf-8') as fh:
            pub = fh.read().strip()
        print(f'from="{args.print_authorized_keys}",restrict,command="{INVENTORY_COMMAND}" {pub}')
        return
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format=LOGGING_FORMAT)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    dotenv.load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
    for var in ('NB_URL', 'NB_TOKEN'):
        if not os.environ.get(var):
            sys.exit(f'{var} is not set')

    nb = pynetbox.api(os.environ['NB_URL'], token=os.environ['NB_TOKEN'])
    clusters = list(nb.virtualization.clusters.filter(cf_proxmox_sync_enabled=True))
    if args.cluster:
        wanted = {c.lower() for c in args.cluster}
        clusters = [c for c in nb.virtualization.clusters.all() if c.name.lower() in wanted]
        missing = wanted - {c.name.lower() for c in clusters}
        if missing:
            sys.exit(f'NetBox cluster(s) not found: {", ".join(sorted(missing))}')
    if not clusters:
        sys.exit('No NetBox clusters have proxmox_sync_enabled set')

    failed = []
    for cluster in clusters:
        cf = cluster.custom_fields or {}
        secret_var = env_secret_name(cluster.name)
        missing = [n for n, v in (('proxmox_token_id', cf.get('proxmox_token_id')),
                                  (secret_var, os.environ.get(secret_var))) if not v]
        if missing:
            logger.error(f'[{cluster.name}] skipped: {", ".join(missing)} not set')
            failed.append(cluster.name)
            continue
        verify = bool(cf.get('proxmox_verify_tls'))
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        node_map = dict(p.strip().split('=', 1) for p in (cf.get('proxmox_node_map') or '').split(',') if '=' in p)
        pve, seed = connect(nb, cluster, cf['proxmox_token_id'], os.environ[secret_var], verify)
        if pve is None:
            failed.append(cluster.name)
            continue
        plan = Plan(args.dry_run, cluster.name)
        try:
            sync = ClusterSync(nb, cluster, pve, plan, seed)
            sync.carry_map = {o.strip().lower(): n.strip().lower() for o, n in
                              (p.split('=', 1) for p in args.carry_map.split(',') if '=' in p)}
            ok = sync.run(node_map)
        except Exception:  # pylint: disable=broad-except
            logger.exception(f'[{cluster.name}] sync failed')
            ok = False
        logger.info(f'[{cluster.name}] done%s: %s', ' (dry run, nothing written)' if args.dry_run else '',
                    ', '.join(f'{k} {n}' for k, n in plan.counts.items()))
        if not ok:
            failed.append(cluster.name)
    if failed:
        sys.exit(f'Failed: {", ".join(failed)}')


if __name__ == '__main__':
    main()
