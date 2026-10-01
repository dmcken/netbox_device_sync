'''RouterOS REST API transport, mimicking the slice of librouteros's API
that drivers.routeros uses (``path(*parts)`` -> iterable of dicts, plus
``close()``), so the driver can run unchanged against devices where only
the REST API (``/ip service www``/``www-ssl``) is enabled and the binary
API service (8728/8729) is off.

REST returns every value as a string; librouteros converts them, and the
driver relies on that (e.g. ``entry['disabled'] is True``), so values are
converted the same way librouteros does: integers to int, and
yes/true/no/false to bool.
'''

# System import
import logging

# External import
import requests
import urllib3

logger = logging.getLogger(__name__)

_BOOL_WORDS = {'yes': True, 'true': True, 'no': False, 'false': False}


def _convert(value):
    '''Convert a REST string value the way librouteros converts API words.'''
    if not isinstance(value, str):
        return value
    try:
        return int(value)
    except ValueError:
        return _BOOL_WORDS.get(value, value)


class RestError(Exception):
    '''A REST request failed (connection, HTTP status or an error body).'''


class _RestPath:
    '''Lazy, re-iterable result of RestDevice.path() - fetched on iteration,
    like a librouteros Path.'''

    def __init__(self, device: 'RestDevice', parts: tuple[str, ...]):
        self._device = device
        self._parts = parts

    def __iter__(self):
        return iter(self._device.get('/'.join(self._parts)))


class RestDevice:
    '''Minimal RouterOS REST client.'''

    def __init__(self, host: str, username: str, password: str,
                 scheme: str = 'http', timeout: int = 30) -> None:
        self._base_url = f"{scheme}://{host}/rest"
        self._timeout = timeout
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get(self, rel_path: str) -> list[dict]:
        '''GET /rest/<rel_path>, returning a list of converted dicts.'''
        url = f"{self._base_url}/{rel_path}"
        try:
            resp = self._session.get(url, timeout=self._timeout)
        except requests.RequestException as exc:
            raise RestError(f"GET {url} failed: {exc}") from exc
        if resp.status_code == 401:
            raise RestError(f"GET {url}: 401 Unauthorized")
        try:
            body = resp.json()
        except ValueError as exc:
            raise RestError(f"GET {url}: HTTP {resp.status_code}, non-JSON body") from exc
        if not resp.ok or (isinstance(body, dict) and 'error' in body):
            raise RestError(f"GET {url}: HTTP {resp.status_code} {body}")
        if isinstance(body, dict):  # singleton menus, e.g. /system/identity
            body = [body]
        return [{k: _convert(v) for k, v in row.items()} for row in body]

    def path(self, *parts: str) -> _RestPath:
        '''Same call shape as librouteros's Api.path().'''
        return _RestPath(self, parts)

    def close(self) -> None:
        self._session.close()
