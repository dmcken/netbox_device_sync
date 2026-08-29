'''Tiny shared helper used by both Ubiquiti driver families
(drivers/_ubnt_cgi_common.py's AirOS/AirFiber and drivers/uisp.py) -
factored out here rather than duplicated since the two otherwise use
unrelated code paths (different auth/data shapes), but both hit the
exact same real-world quirk.
'''
import collections

import drivers.base


def dedupe_macs_by_plugged(
    interfaces_with_plugged: list[tuple[drivers.base.Interface, bool | None]],
) -> None:
    '''Some Ubiquiti hardware reports the identical MAC on more than one
    interface - confirmed live on an AirFiber 60 HD (ueth0/ueth1/br0 all
    share one MAC, with no bridge.N.port config to explain why) and a
    UISP-firmware AirFiber 60 XR (eth0/eth1 share one MAC). NetBox's
    managed-MAC model rejects assigning the same MAC to two interfaces
    at once, so a shared MAC must always collapse to exactly one
    interface before returning interfaces to the caller - there is no
    "leave it ambiguous" option, since any duplicate left in is a
    guaranteed write failure later.

    Preference order for which interface keeps the MAC:
    1. The one interface whose `status.plugged` is True, if exactly one
       candidate qualifies - confirmed live (EdgePower, UISP AirFiber 60
       XR) that the "extra" copies were on an unplugged/inactive port.
    2. Otherwise (none, or more than one, plugged - confirmed live on an
       AirFiber 60 HD's bonded uEthernet pair, where both physical ports
       are legitimately plugged=True at once) fall back to the first
       candidate in the given order, so the result is always
       deterministic rather than a guess that happens to vary run to
       run.

    Mutates the Interface objects' mac_address lists in place.
    '''
    by_mac: dict[str, list[tuple[drivers.base.Interface, bool | None]]] = (
        collections.defaultdict(list)
    )
    for iface, plugged in interfaces_with_plugged:
        for mac in iface.mac_address:
            by_mac[mac].append((iface, plugged))

    for mac, candidates in by_mac.items():
        if len(candidates) < 2:
            continue

        plugged_candidates = [c for c in candidates if c[1] is True]
        keep_iface = (
            plugged_candidates[0][0] if len(plugged_candidates) == 1 else candidates[0][0]
        )

        for iface, _ in candidates:
            if iface is not keep_iface:
                iface.mac_address = [m for m in iface.mac_address if m != mac]
