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
    addresses = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(
        parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM
    ):
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global:
            raise ValueError("blocked destination")
        addresses.append(address)
    if not addresses:
        raise ValueError("destination has no address")
    # Pin the connection to a checked address. A second DNS lookup by the HTTP
    # transport would otherwise leave a DNS rebinding window.
    return str(next((a for a in addresses if a.version == 4), addresses[0]))

def fetch(url, etag=None, last_modified=None):
    headers = {"User-Agent": USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    with httpx.Client(timeout=httpx.Timeout(20, connect=5), follow_redirects=False,
                      trust_env=False) as client:
        for _ in range(4):
            address = validate_url(url)
            parsed = urlparse(url)
            pinned_url = httpx.URL(url).copy_with(host=address)
            request_headers = {**headers, "Host": parsed.netloc}
            with client.stream("GET", pinned_url, headers=request_headers,
                               extensions={"sni_hostname": parsed.hostname}) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    target = response.headers.get("location")
                    if not target:
                        raise ValueError("redirect without location")
                    url = str(httpx.URL(url).join(target))
                    continue
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_BODY:
                        raise ValueError("oversized response")
                return response.status_code, bytes(body), dict(response.headers), url
    raise ValueError("too many redirects")
