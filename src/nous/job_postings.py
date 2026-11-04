"""Versioned published-job adapters built on publisher APIs and standard JSON parsing.

No descriptions or application forms are retained. Classification is evidence-
based and conservative: a job must be explicitly in Japan and in a technical
security function. Unknown locations/roles are never silently promoted.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SECURITY = re.compile(
    r"(?:security|cyber.?sec|appsec|devsecops|secops|csirt|"
    r"\bsoc\b|incident.response|vulnerabilit|threat.intelligence|"
    r"penetration.test|pentest|red.team|blue.team|identity.access|"
    r"セキュリティ|サイバー|脆弱性|インシデント|脅威インテリジェンス|"
    r"情報保護|ゼロトラスト)",
    re.IGNORECASE,
)
_NONTECHNICAL = re.compile(
    r"(?:\bsales\b|\baccount.executive\b|\bbusiness.development\b|"
    r"営業|販売促進|プリセールス|セールス|警備)",
    re.IGNORECASE,
)
_JAPAN = re.compile(
    r"(?:\bjapan\b|\bjp\b|\bjpn\b|\btokyo\b|\bosaka\b|"
    r"\bkyoto\b|\byokohama\b|\bnagoya\b|\bfukuoka\b|"
    r"\bsapporo\b|\bkobe\b|\bchiba\b|\bsaitama\b|\bkanagawa\b|"
    r"日本|東京|大阪|京都|横浜|名古屋|福岡|札幌|神戸|千葉|埼玉|神奈川)",
    re.IGNORECASE,
)
_JP_COUNTRIES = {"JP", "JPN", "JAPAN", "日本"}
_ADAPTERS = {"greenhouse_jobs_v1", "lever_jobs_v1", "ashby_jobs_v1"}


def _text(value, limit=200):
    return value.strip()[:limit] if isinstance(value, str) else ""


def _timestamp(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # Lever uses epoch milliseconds; never interpret it as seconds.
        try:
            return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _department(job, adapter):
    if adapter == "greenhouse_jobs_v1":
        values = job.get("departments") or []
        if not isinstance(values, list):
            raise ValueError("invalid Greenhouse departments")
        return ", ".join(_text(item.get("name")) for item in values
                         if isinstance(item, dict))[:200]
    if adapter == "lever_jobs_v1":
        categories = job.get("categories") or {}
        if not isinstance(categories, dict):
            raise ValueError("invalid Lever categories")
        return _text(categories.get("department") or categories.get("team"))
    return _text(job.get("department") or job.get("team"))


def _locations(job, adapter):
    if adapter == "greenhouse_jobs_v1":
        location = job.get("location") or {}
        if not isinstance(location, dict):
            raise ValueError("invalid Greenhouse location")
        values = [(None, _text(location.get("name")))]
        for office in job.get("offices") or []:
            if isinstance(office, dict):
                values.append((None, _text(office.get("location") or office.get("name"))))
        return values
    if adapter == "lever_jobs_v1":
        categories = job.get("categories") or {}
        if not isinstance(categories, dict):
            raise ValueError("invalid Lever categories")
        values = [(job.get("country"), _text(categories.get("location")))]
        for location in categories.get("allLocations") or []:
            if isinstance(location, str):
                values.append((job.get("country"), _text(location)))
        return values
    address = job.get("address") or {}
    postal = address.get("postalAddress") or {} if isinstance(address, dict) else {}
    values = [(postal.get("addressCountry"), _text(job.get("location")))]
    for extra in job.get("secondaryLocations") or []:
        if not isinstance(extra, dict):
            continue
        ext_addr = extra.get("address") or {}
        values.append((ext_addr.get("addressCountry") if isinstance(ext_addr, dict) else None,
                       _text(extra.get("location"))))
    return values


def _japan_evidence(locations):
    for country, label in locations:
        country_name = _text(country).upper()
        if country_name in _JP_COUNTRIES:
            return label, "country:JP"
        # Explicitly foreign country overrides ambiguous location text.
        if country_name:
            continue
        if _JAPAN.search(label):
            return label, "location:Japan"
    return None


def _security_evidence(title, department):
    if _NONTECHNICAL.search(title):
        return None
    if _SECURITY.search(title):
        return "title:security"
    if _SECURITY.search(department):
        return "department:security"
    return None


def _records(adapter, content):
    data = json.loads(content)
    if adapter == "lever_jobs_v1":
        if not isinstance(data, list):
            raise ValueError("Lever postings API must return a list")
        return data
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), list):
        raise ValueError("ATS board must return a jobs array")
    return data["jobs"]


def extract_jobs(adapter, content, *, job_filter="japan_security"):
    """Extract only metadata from a *complete* board/page response.

    The caller is responsible for ensuring all pages were received before
    treating missing records as withdrawn.
    """
    if adapter not in _ADAPTERS:
        raise ValueError("unsupported job adapter")
    if job_filter != "japan_security":
        raise ValueError("unsupported job filter")
    rows = _records(adapter, content)
    result = []
    for job in rows:
        if not isinstance(job, dict):
            raise ValueError("invalid job entry")
        if adapter == "ashby_jobs_v1" and job.get("isListed") is False:
            continue
        title = _text(job.get("title") if adapter != "lever_jobs_v1" else job.get("text"), 1000)
        if not title:
            raise ValueError("job title missing")
        department = _department(job, adapter)
        security_evidence = _security_evidence(title, department)
        if security_evidence is None:
            continue
        japan = _japan_evidence(_locations(job, adapter))
        if japan is None:
            continue
        location, location_evidence = japan
        if adapter == "greenhouse_jobs_v1":
            url = job.get("absolute_url")
            identifier = job.get("id")
            published, updated = job.get("first_published"), job.get("updated_at")
            employment, workplace = None, None
        elif adapter == "lever_jobs_v1":
            url = job.get("hostedUrl")
            identifier = job.get("id")
            published, updated = _timestamp(job.get("createdAt")), _timestamp(job.get("updatedAt"))
            categories = job.get("categories") or {}
            employment, workplace = categories.get("commitment"), job.get("workplaceType")
        else:
            url = job.get("jobUrl")
            identifier = job.get("id") or url
            published, updated = job.get("publishedAt"), None
            employment, workplace = job.get("employmentType"), job.get("workplaceType")
        parsed = urlsplit(url) if isinstance(url, str) else None
        if (parsed is None or parsed.scheme != "https" or not parsed.hostname or
                parsed.username or parsed.password):
            raise ValueError("published job URL must be a safe HTTPS link")
        if not isinstance(identifier, (str, int)) or not str(identifier):
            raise ValueError("published job ID missing")
        if len(str(identifier)) > 250:
            raise ValueError("published job ID too long")
        result.append({
            "id": str(identifier), "url": url, "title": title,
            "published": _timestamp(published), "updated": _timestamp(updated),
            "job": {
                "provider": adapter.replace("_jobs_v1", ""),
                "country": "JP",
                "location": location,
                "department": department,
                "employment_type": _text(employment, 80) or None,
                "workplace_type": _text(workplace, 80) or None,
                "classification": "japan_security",
                "evidence": [security_evidence, location_evidence],
            },
        })
    return result


class IncompleteBoard(ValueError):
    """The source has more pages than the bounded poll is permitted to read."""


def lever_page_url(base, *, offset, limit):
    """Preserve the approved Lever board endpoint, modifying only paging keys."""
    parsed = urlsplit(base)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if set(params) - {"mode", "skip", "limit"}:
        raise ValueError("unsupported Lever board query")
    params.update({"mode": "json", "skip": str(offset), "limit": str(limit)})
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params), ""))


def fetch_lever_board(source, fetcher):
    """Read an entire Lever board or fail without returning partial records.

    fetcher is the existing SSRF-pinned bounded Nous fetch. The worker records
    every page request against the per-source hourly budget.
    """
    limit = 100
    max_pages = source.config.get("max_pages", 1)
    records = []
    last_headers, last_url = {}, source.url
    for page in range(max_pages):
        url = lever_page_url(source.url, offset=page * limit, limit=limit)
        status, body, headers, last_url = fetcher(url, None, None)
        if status == 304:
            raise ValueError("unexpected conditional response from unconditional Lever board fetch")
        if status != 200:
            return status, [], headers, last_url
        raw_page = _records("lever_jobs_v1", body)
        records.extend(extract_jobs("lever_jobs_v1", body))
        last_headers = headers
        if len(raw_page) < limit:
            return 200, records, last_headers, last_url
    raise IncompleteBoard(f"Lever board exceeds {max_pages} page(s); no partial snapshot committed")
