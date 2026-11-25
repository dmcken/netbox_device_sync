'''RouterOS SSH transport, mimicking the slice of librouteros's API that
drivers.routeros uses (``path(*parts)`` -> iterable of dicts, plus
``close()``), for devices where neither the binary API (8728/8729) nor
the REST API (``/ip service www``) is enabled and SSH is the only way in.

Each menu is read with ``print detail as-value`` and serialised to JSON
on the router itself (``:serialize to=json``, RouterOS 7.13+), so no
screen-scraping of the CLI's column layout is involved.

The JSON differs from what the API/REST transports return in one way the
driver cares about: multi-valued properties (a bond's ``slaves``, a
neighbour's ``interface``/``discovered-by``) arrive as JSON arrays rather
than a comma-joined string. They are joined back here so the driver sees
the same shape whichever transport answered. An interface's automatic MTU
also reads back as 0 rather than the word 'auto'.

Live counters some menus compute on request (an IP pool's used/total/
available) are not part of ``print as-value`` and are simply absent.
'''

# System import
import json
import logging

# External import
import paramiko

logger = logging.getLogger(__name__)


class SshError(Exception):
    '''An SSH request failed (connection, command error or bad output).'''


class SshAuthError(SshError):
    '''The device rejected the credentials.'''


def _convert(value):
    '''Flatten a JSON value to what the API/REST transports would return.'''
    if isinstance(value, list):
        return ','.join(str(item) for item in value)
    return value


class _SshPath:
    '''Lazy, re-iterable result of SshDevice.path() - fetched on iteration,
    like a librouteros Path.'''

    def __init__(self, device: 'SshDevice', parts: tuple[str, ...]):
        self._device = device
        self._parts = parts

    def __iter__(self):
        return iter(self._device.get('/'.join(self._parts)))


class SshDevice:
    '''Minimal RouterOS-over-SSH client.'''

    def __init__(self, host: str, username: str, password: str,
                 port: int = 22, timeout: int = 30) -> None:
        self._host = host
        self._timeout = timeout
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self._client.connect(
                host, port=port, username=username, password=password,
                timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                look_for_keys=False, allow_agent=False,
            )
        except paramiko.AuthenticationException as exc:
            raise SshAuthError(f"SSH to {host}: authentication failed") from exc
        except (paramiko.SSHException, OSError) as exc:
            raise SshError(f"SSH to {host} failed: {exc}") from exc

    def _run(self, command: str) -> str:
        try:
            _stdin, stdout, _stderr = self._client.exec_command(command, timeout=self._timeout)
            return stdout.read().decode('utf-8', errors='replace')
        except (paramiko.SSHException, OSError) as exc:
            raise SshError(f"SSH command on {self._host} failed: {exc}") from exc

    def get(self, rel_path: str) -> list[dict]:
        '''Read one menu (e.g. 'ip/neighbor'), returning a list of dicts.'''
        # A list menu is printed; a singleton menu (/system/identity) has
        # no 'print detail' and is read with 'get' instead.
        output = ''
        for command in (f"/{rel_path}/print detail as-value", f"/{rel_path}/get"):
            output = self._run(f":put [:serialize to=json value=[{command}]]").strip()
            try:
                body = json.loads(output)
                break
            except ValueError:
                continue
        else:
            # Not JSON either way: the router's own error text (no such
            # menu, a RouterOS too old for :serialize, a policy refusal).
            raise SshError(
                f"SSH read of /{rel_path} on {self._host}: {output[:200]!r}"
            )
        if isinstance(body, dict):
            body = [body]
        rows = [{k: _convert(v) for k, v in row.items()} for row in body]
        for row in rows:
            if row.get('mtu') == 0:
                row['mtu'] = 'auto'
        return rows

    def path(self, *parts: str) -> _SshPath:
        '''Same call shape as librouteros's Api.path().'''
        return _SshPath(self, parts)

    def close(self) -> None:
        self._client.close()
