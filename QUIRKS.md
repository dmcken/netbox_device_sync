# Tachyon Networks TNS-100 - API quirks

Found while building `drivers/tachyon.py` against a real TNS-100 (hostname
`AUS-TS02`, 10.14.1.7, firmware `firmux 1.12.6 rev 54713`, serial
`TNS1001252300369`). Raised here for reporting back to Tachyon.

## A read-only account can't read config (including VLANs) through either config endpoint

The web UI's own JS (`app.jsx`) picks which config endpoint to call based on
the logged-in user's `level`:

```js
config_url = (level === 0) ? "/cgi.lua/config" : "/cgi.lua/config_installer"
```

i.e. an admin (`level: 0`) uses `/cgi.lua/config`, and every other level is
expected to use `/cgi.lua/config_installer` instead. In practice, a
read-only account (`level: 9` in our case) gets `401 Unauthorized` on
**both**:

```
GET /cgi.lua/config            -> {"statusCode":401,"error":{"details":"Authorization Failed","path":"/cgi.lua/config"},"description":"Unauthorized"}
GET /cgi.lua/config_installer   -> {"statusCode":401,"error":{"details":"Authorization Failed","path":"/cgi.lua/config_installer"},"description":"Unauthorized"}
```

If `config_installer` is meant to be the non-admin path to (presumably
read-only) config access, it isn't actually reachable by a non-admin
account on this firmware. If it's intentional that read-only accounts have
no config access at all, the client-side `config_url` logic above is
misleading - it implies there's a config endpoint available for every
authenticated level.

Practical effect on our end: `config()` is the only endpoint that exposes
this device's configured VLANs (`network.zones.wan.vlans` - `status()`
doesn't carry VLAN definitions at all) - so a monitoring/inventory
integration that only needs to read VLAN membership still needs a full
admin-level account to get it, rather than the read-only account we'd
prefer to grant it.
