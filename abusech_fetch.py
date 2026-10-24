"""
abusech_fetch.py — keyed abuse.ch feeds -> plain newline-separated domain list.

abuse.ch retired its keyless downloads (HTTP 410/401). The key is read from the
ABUSECH_AUTH_KEY environment variable and sent ONLY in the `Auth-Key` header,
never in the URL, so it can't leak into logs, warn_log.txt or the generated
blocklist.txt header (which lists every source URL).

Usage (from the workflow's inline python):
    from abusech_fetch import is_abusech_api, abusech_fetch
    if is_abusech_api(url):
        text = abusech_fetch(url)      # one domain per line
"""
import json
import os
import re
import urllib.parse
import urllib.request

URLHAUS_HOST = "urlhaus-api.abuse.ch"
THREATFOX_HOST = "threatfox-api.abuse.ch"
_API_HOSTS = {URLHAUS_HOST, THREATFOX_HOST}

_RE_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# ThreatFox: only keep reasonably confident domain IOCs.
THREATFOX_MIN_CONFIDENCE = 75
THREATFOX_DAYS = 7  # API maximum


class MissingKey(RuntimeError):
    pass


def is_abusech_api(url: str) -> bool:
    return (urllib.parse.urlparse(url).hostname or "").lower() in _API_HOSTS


def source_label(url: str) -> str:
    """Short human label for logs (the URL path tail is empty/meaningless here)."""
    return (urllib.parse.urlparse(url).hostname or "abuse.ch").lower()


def _clean_host(h) -> str:
    h = (h or "").strip().lower().rstrip(".")
    if not h or "." not in h or _RE_IPV4.match(h) or ":" in h:
        return ""  # drop IPs / IPv6 / junk — this is a DNS blocklist
    return h


def _request(url: str, key: str, timeout: int):
    headers = {"Auth-Key": key, "User-Agent": "DNS-Builder/1.0"}
    host = urllib.parse.urlparse(url).hostname.lower()
    if host == THREATFOX_HOST:
        body = json.dumps({"query": "get_iocs", "days": THREATFOX_DAYS}).encode()
        headers["Content-Type"] = "application/json"
        return urllib.request.Request(url, data=body, headers=headers, method="POST")
    return urllib.request.Request(url, headers=headers)


def abusech_fetch(url: str, timeout: int = 30) -> str:
    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        raise MissingKey("abuse.ch Auth-Key secret not set")

    host = urllib.parse.urlparse(url).hostname.lower()
    with urllib.request.urlopen(_request(url, key, timeout), timeout=timeout) as r:
        payload = json.loads(r.read().decode("utf-8", errors="ignore"))

    status = payload.get("query_status")
    if status != "ok":
        # e.g. unknown_auth_key, no_results, illegal_days ...
        raise RuntimeError(f"abuse.ch query_status={status}")

    hosts = set()
    if host == THREATFOX_HOST:
        for item in payload.get("data") or []:
            if item.get("ioc_type") != "domain":
                continue
            if int(item.get("confidence_level") or 0) < THREATFOX_MIN_CONFIDENCE:
                continue
            h = _clean_host(item.get("ioc"))
            if h:
                hosts.add(h)
    else:  # URLhaus: recent malware-distribution URLs
        for item in payload.get("urls") or []:
            if item.get("url_status") != "online":
                continue
            h = item.get("host") or urllib.parse.urlparse(item.get("url", "")).hostname
            h = _clean_host(h)
            if h:
                hosts.add(h)

    return "\n".join(sorted(hosts))
