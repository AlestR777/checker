"""Verified HTTPS downloads only. Never disable TLS verification; never fetch victim hosts."""
from __future__ import annotations
import gzip
import json
import os
import ssl
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler
from urllib.error import URLError

UA = 'ThreatWatchFrance/2.0 (defensive OSINT; public metadata)'

class HTTPSOnlyRedirect(HTTPRedirectHandler):
    def __init__(self, allowed_hosts=None):
        self.allowed_hosts = set(allowed_hosts or [])
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != 'https':
            raise ValueError('Refusing non-HTTPS redirect')
        if self.allowed_hosts and urlsplit(newurl).hostname not in self.allowed_hosts:
            raise ValueError('Refusing redirect outside editorial-host allowlist')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def ssl_context():
    """Prefer native trust store (important on Windows), then a supported CA bundle."""
    custom = os.environ.get('THREATWATCH_CA_BUNDLE') or os.environ.get('SSL_CERT_FILE')
    if custom:
        return ssl.create_default_context(cafile=custom)
    try:
        import truststore
        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except ImportError:
        pass
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def fetch_bytes(url: str, *, timeout: int = 18, max_bytes: int = 2_000_000, accept: str = 'application/rss+xml, application/atom+xml, application/xml, application/json, text/xml', allowed_hosts=None) -> bytes:
    u = urlsplit(url)
    if u.scheme != 'https' or not u.hostname or u.username or u.password:
        raise ValueError('Only public HTTPS feed/API endpoints are accepted')
    if allowed_hosts and (u.hostname not in set(allowed_hosts) or u.port not in (None,443)):
        raise ValueError('Not in editorial-host allowlist')
    req = Request(url, headers={'User-Agent': UA, 'Accept': accept, 'Accept-Encoding': 'gzip'})
    opener = build_opener(HTTPSHandler(context=ssl_context()), HTTPSOnlyRedirect(allowed_hosts))
    try:
        with opener.open(req, timeout=timeout) as response:
            if urlsplit(response.url).scheme != 'https':
                raise ValueError('Refusing non-HTTPS response')
            if allowed_hosts and urlsplit(response.url).hostname not in set(allowed_hosts):
                raise ValueError('Outside editorial-host allowlist')
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError('Feed exceeds configured size limit')
            if 'gzip' in response.headers.get('Content-Encoding', '').lower():
                data = gzip.decompress(data)
                if len(data) > max_bytes:
                    raise ValueError('Decompressed feed exceeds configured size limit')
            return data
    except (ssl.SSLCertVerificationError, URLError) as exc:
        if 'CERTIFICATE_VERIFY_FAILED' in str(exc):
            raise RuntimeError('TLS certificate verification failed. On Windows run: python -m pip install -U truststore certifi; for a trusted company proxy set THREATWATCH_CA_BUNDLE to its CA PEM file. TLS verification is never disabled.') from exc
        raise


def fetch_json(url: str, **kwargs):
    return json.loads(fetch_bytes(url, accept='application/json', **kwargs).decode('utf-8-sig'))
