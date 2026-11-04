"""Native ATS parsing and completeness boundaries: no live network or secrets."""
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import ValidationError

from nous.job_postings import IncompleteBoard, extract_jobs, fetch_lever_board, lever_page_url
from nous.registry import SourceConfig, load_registry


def encoded(value):
    return json.dumps(value, ensure_ascii=False).encode()


def test_greenhouse_filters_japan_security_without_storing_description():
    jobs = [
        {"id": 13, "title": "Security Architect", "absolute_url": "https://boards.greenhouse.io/example/jobs/13",
         "location": {"name": "Tokyo, Japan"}, "updated_at": "2026-11-03T00:00:00Z",
         "content": "never store this personally identifying description"},
        {"id": 14, "title": "Security Engineer", "absolute_url": "https://example.com/jobs/14",
         "location": {"name": "California, United States"}},
        {"id": 15, "title": "Security Sales", "absolute_url": "https://example.com/jobs/15",
         "location": {"name": "Tokyo"}},
        {"id": 16, "title": "Security Engineer", "absolute_url": "https://example.com/jobs/16",
         "location": {"name": "Remote"}},
        {"id": 17, "title": "ソフトウェアエンジニア", "absolute_url": "https://example.com/jobs/17",
         "location": {"name": "東京"}, "departments": [{"name": "Security Engineering"}]},
    ]
    result = extract_jobs("greenhouse_jobs_v1", encoded({"jobs": jobs}))
    assert [r["id"] for r in result] == ["13", "17"]
    assert result[0]["job"]["country"] == "JP"
    assert result[0]["job"]["evidence"] == ["title:security", "location:Japan"]
    assert result[1]["job"]["evidence"][0] == "department:security"
    assert "content" not in str(result)


def test_ashby_filters_unlisted_and_accepts_secondary_japan_office():
    jobs = [
        {"title": "Cybersecurity Lead", "jobUrl": "https://jobs.ashbyhq.com/example/1",
         "location": "San Francisco", "address": {"postalAddress": {"addressCountry": "USA"}},
         "secondaryLocations": [{"location": "Tokyo", "address": {"addressCountry": "JPN"}}],
         "isListed": True, "descriptionPlain": "secret body", "employmentType": "FullTime"},
        {"title": "Security Architect", "jobUrl": "https://jobs.ashbyhq.com/example/2",
         "location": "Tokyo", "isListed": False},
    ]
    result = extract_jobs("ashby_jobs_v1", encoded({"jobs": jobs}))
    assert len(result) == 1
    assert result[0]["id"] == "https://jobs.ashbyhq.com/example/1"
    assert result[0]["job"]["location"] == "Tokyo"
    assert result[0]["job"]["employment_type"] == "FullTime"
    assert "secret body" not in str(result)


def test_lever_epoch_times_country_and_sales_exclusion():
    result = extract_jobs("lever_jobs_v1", encoded([
        {"id": "abc", "text": "クラウドセキュリティエンジニア",
         "hostedUrl": "https://jobs.lever.co/example/abc", "country": "JP",
         "categories": {"location": "Remote", "department": "Infrastructure"},
         "createdAt": 1730678400000, "updatedAt": 1730678500000},
        {"id": "def", "text": "Security Account Executive",
         "hostedUrl": "https://jobs.lever.co/example/def", "country": "JP",
         "categories": {"location": "Tokyo"}},
        {"id": "ghi", "text": "Security Engineer",
         "hostedUrl": "https://jobs.lever.co/example/ghi", "country": "US",
         "categories": {"location": "Tokyo"}},
    ]))
    assert len(result) == 1
    assert result[0]["id"] == "abc"
    assert result[0]["published"].endswith("+00:00")
    assert result[0]["job"]["evidence"][1] == "country:JP"


def test_lever_pagination_is_bounded_complete_and_fails_closed():
    url = "https://api.lever.co/v0/postings/example"
    calls = []
    page1 = [
        {"id": "id-" + str(i), "text": "Security Engineer" if i == 1 else "Other role",
         "hostedUrl": "https://jobs.lever.co/example/" + str(i), "country": "JP",
         "categories": {"location": "Tokyo"}} for i in range(100)
    ]
    page2 = [
        {"id": "id-100", "text": "Security Lead",
         "hostedUrl": "https://jobs.lever.co/example/100", "country": "JP",
         "categories": {"location": "Tokyo"}},
    ]

    def fetcher(path, etag, modified):
        assert etag is None and modified is None
        params = parse_qs(urlsplit(path).query)
        calls.append(path)
        assert params["mode"] == ["json"] and params["limit"] == ["100"]
        return 200, encoded(page1 if params["skip"] == ["0"] else page2), {}, path

    source = SimpleNamespace(url=url, config={"max_pages": 2})
    status, records, headers, final_url = fetch_lever_board(source, fetcher)
    assert status == 200
    assert [r["id"] for r in records] == ["id-1", "id-100"]
    assert len(calls) == 2
    assert final_url.endswith("skip=100&limit=100")

    source.config["max_pages"] = 1
    with pytest.raises(IncompleteBoard):
        fetch_lever_board(source, fetcher)

    source.config["max_pages"] = 2

    def partial_then_rate_limited(path, etag, modified):
        if parse_qs(urlsplit(path).query)["skip"] == ["0"]:
            return 200, encoded(page1), {}, path
        return 429, b"", {"retry-after": "60"}, path

    status, records, _, _ = fetch_lever_board(source, partial_then_rate_limited)
    assert status == 429 and records == []


def test_native_ats_registry_requires_official_endpoints():
    config = next(c for c in load_registry("sources") if c.id == "sie-japan-careers")
    assert config.adapter == "greenhouse_jobs_v1"
    assert config.enabled is False
    bad = config.model_dump()
    bad["url"] = "https://example.org/v1/boards/siei/jobs"
    with pytest.raises(ValidationError, match="official public GET endpoint"):
        SourceConfig.model_validate(bad)
    bad = config.model_dump()
    bad["adapter"] = "lever_jobs_v1"
    bad["url"] = "https://api.lever.co/v0/postings/example"
    bad["max_pages"] = 5
    bad["max_requests_per_hour"] = 4
    with pytest.raises(ValidationError, match="hourly request budget"):
        SourceConfig.model_validate(bad)
    bad["max_pages"] = 2
    assert SourceConfig.model_validate(bad).max_pages == 2
    assert lever_page_url(bad["url"], offset=100, limit=100).endswith(
        "mode=json&skip=100&limit=100"
    )
