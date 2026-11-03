import json
from urllib.parse import urljoin
import feedparser
from bs4 import BeautifulSoup

def extract(source, content, base_url):
    kind = source.kind
    if kind == "rss":
        feed = feedparser.parse(content)
        if feed.bozo and not feed.entries:
            raise ValueError("invalid feed")
        return [{"id": e.get("id") or e.get("link"), "url": e.get("link"),
                 "title": e.get("title"), "published": e.get("published"),
                 "updated": e.get("updated")} for e in feed.entries]
    if kind == "json_api":
        data = json.loads(content)
        path = source.config.get("json_path")
        for key in path.split(".") if path else []:
            data = data[key]
        if not isinstance(data, list):
            raise ValueError("JSON path must resolve to list")
        mapping = source.config.get("field_map", {})
        def field(entry, name):
            return entry.get(mapping.get(name, name))
        return [{"id": str(field(e, "id") or field(e, "url")), "url": field(e, "url"),
                 "title": field(e, "title"), "published": field(e, "published"),
                 "updated": field(e, "updated")}
                for e in data if isinstance(e, dict)]
    if kind == "html":
        soup = BeautifulSoup(content, "html.parser")
        selectors = source.config["selectors"]
        result = []
        for node in soup.select(selectors["item"]):
            title_node = node.select_one(selectors["title"])
            link_node = node.select_one(selectors["url"])
            if title_node and link_node and link_node.get("href"):
                url = urljoin(base_url, link_node["href"])
                result.append({"id": url, "url": url, "title": title_node.get_text(" ", strip=True)})
        return result
    raise ValueError("unknown adapter")
