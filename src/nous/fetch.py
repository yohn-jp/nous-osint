import ipaddress
import socket
from urllib.parse import urlparse
import httpx

MAX_BODY = 8_000_000
USER_AGENT = "NousOSINT/0.1 (+https://github.com/yohn-jp/nous-osint; public metadata research)"

def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("unsafe URL")
    for family, _, _, _, sockaddr in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM):
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global:
            raise ValueError("blocked destination")

def fetch(url, etag=None, last_modified=None):
    headers = {"User-Agent": USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    with httpx.Client(timeout=httpx.Timeout(20, connect=5), follow_redirects=False) as client:
        for _ in range(4):
            validate_url(url)
            with client.stream("GET", url, headers=headers) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    target = response.headers.get("location")
                    if not target:
                        raise ValueError("redirect without location")
                    url = str(response.url.join(target))
                    continue
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_BODY:
                        raise ValueError("oversized response")
                return response.status_code, bytes(body), dict(response.headers), str(response.url)
    raise ValueError("too many redirects")
