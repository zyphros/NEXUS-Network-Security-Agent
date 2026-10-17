"""Bounded public web search for the desktop research assistant."""

import html
from html.parser import HTMLParser
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
from xml.etree import ElementTree


SEARCH_URL = "https://www.bing.com/search"
MAX_QUERY_CHARS = 200
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RESULTS = 5
MAX_TITLE_CHARS = 240
MAX_SNIPPET_CHARS = 800
MAX_URL_CHARS = 2048
SEARCH_TIMEOUT_SECONDS = 12


class _HTMLTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _plain_text(value: str) -> str:
    parser = _HTMLTextParser()
    parser.feed(value)
    parser.close()
    return " ".join(" ".join(parser.parts).split())


def _safe_url(value: str) -> Optional[str]:
    url = html.unescape(value.strip())
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return url[:MAX_URL_CHARS]


def _parse_results(payload: bytes) -> List[Dict[str, str]]:
    if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
        raise RuntimeError("رفض رد بحث XML غير آمن.")
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exc:
        raise RuntimeError("أعاد محرك البحث موجزًا غير صالح.") from exc

    results = []
    for item in root.findall("./channel/item"):
        title_node = item.find("title")
        link_node = item.find("link")
        description_node = item.find("description")
        title = _plain_text(title_node.text or "") if title_node is not None else ""
        url = _safe_url(link_node.text or "") if link_node is not None else None
        snippet = (
            _plain_text(description_node.text or "")[:MAX_SNIPPET_CHARS]
            if description_node is not None
            else ""
        )
        if title and url:
            results.append(
                {
                    "title": title[:MAX_TITLE_CHARS],
                    "url": url,
                    "snippet": snippet,
                }
            )
        if len(results) == MAX_RESULTS:
            break
    return results


def search_web(query: str) -> List[Dict[str, str]]:
    """Search Bing's public RSS endpoint and return a bounded set of linked excerpts."""
    query = query.strip()
    if not query:
        raise ValueError("اكتب عبارة البحث أولًا.")
    if len(query) > MAX_QUERY_CHARS:
        raise ValueError(f"البحث محدود بـ{MAX_QUERY_CHARS} حرفًا.")

    request = Request(
        f"{SEARCH_URL}?{urlencode({'format': 'rss', 'q': query})}",
        headers={
            "User-Agent": "NEXUS-Desktop-Research/1.0 (public RSS search)",
            "Accept": "application/rss+xml, application/xml, text/xml",
        },
    )
    try:
        with urlopen(request, timeout=SEARCH_TIMEOUT_SECONDS) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise RuntimeError(f"محرك البحث رفض الطلب (HTTP {exc.code}).") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"تعذر الاتصال بمحرك البحث: {exc}") from exc

    if len(payload) > MAX_RESPONSE_BYTES:
        raise RuntimeError("تجاوز رد محرك البحث الحد المسموح لحجم الصفحة.")
    results = _parse_results(payload)
    if not results:
        raise RuntimeError("لم يُرجع محرك البحث نتائج قابلة للعرض.")
    return results
