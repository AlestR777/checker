"""Exclusive local sockets and verification of the newly launched instance."""
from __future__ import annotations
import errno
import json
import socket
import time
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler


class ExclusiveLocalHTTPServer(ThreadingHTTPServer):
    # On Windows SO_REUSEADDR can bind an address already used by an old copy.
    allow_reuse_address = False
    allow_reuse_port = False

    def server_bind(self):
        exclusive = getattr(socket, 'SO_EXCLUSIVEADDRUSE', None)
        if exclusive is not None:
            self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        super().server_bind()


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('Local startup check was redirected; refusing to open an unverified server')


def verify_server(base_url, *, instance_id, version, timeout=3.0):
    """Check a loopback-only server without sending its identity through a proxy."""
    parsed = urlsplit(base_url)
    if (parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1','localhost','::1'}
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {'','/','/api/runtime'}):
        raise ValueError('Startup verification accepts only a local HTTP runtime endpoint')
    if not instance_id or not version or timeout <= 0:
        raise ValueError('Expected instance, version and positive timeout are required')
    endpoint = f'http://{parsed.netloc}/api/runtime'
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    deadline = time.monotonic() + timeout
    while True:
        try:
            with opener.open(endpoint, timeout=max(.05,deadline-time.monotonic())) as response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise RuntimeError('Local startup response is too large')
                info = json.loads(raw)
            break
        except HTTPError as exc:
            raise RuntimeError(f'Startup check got HTTP {exc.code}; this is not the expected ThreatWatch server') from exc
        except URLError as exc:
            reason = exc.reason
            if (getattr(reason,'errno',None) == errno.ECONNREFUSED
                    or getattr(reason,'winerror',None) == 10061) and time.monotonic() < deadline:
                time.sleep(min(.05,max(0,deadline-time.monotonic())))
                continue
            raise RuntimeError('Could not verify the newly started local ThreatWatch server') from exc
        except (ValueError, OSError) as exc:
            raise RuntimeError('Local startup response could not be verified') from exc
    if not isinstance(info,dict) or info.get('instance_id') != instance_id or info.get('version') != version:
        raise RuntimeError('Another server answered the startup check; browser opening cancelled')
    return info
