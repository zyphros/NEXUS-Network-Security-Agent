import io
import json
import unittest
from urllib.error import URLError
from unittest.mock import patch

import network_threat_detection as agent
from web_research import _parse_results
from web_research import (
    MAX_QUERY_CHARS,
    MAX_RESPONSE_BYTES,
    SEARCH_URL,
    search_web,
)


class WebResearchTests(unittest.TestCase):
    def test_rss_results_extract_titles_urls_and_html_snippets(self):
        rss = b"""<?xml version="1.0"?>
        <rss><channel>
          <item><title>Security &amp; privacy guide</title>
            <link>https://example.com/guide</link>
            <description>A &lt;b&gt;useful&lt;/b&gt; public summary.</description>
          </item>
          <item><title>Second source</title>
            <link>https://example.org/report</link><description>Another summary</description>
          </item>
        </channel></rss>
        """
        with patch("web_research.urlopen", return_value=io.BytesIO(rss)) as urlopen:
            results = search_web("  network security  ")

        request = urlopen.call_args.args[0]
        self.assertTrue(request.full_url.startswith(SEARCH_URL + "?"))
        self.assertIn("format=rss", request.full_url)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["title"], "Security & privacy guide")
        self.assertEqual(results[0]["url"], "https://example.com/guide")
        self.assertEqual(results[0]["snippet"], "A useful public summary.")
        self.assertEqual(results[1]["url"], "https://example.org/report")

    def test_results_reject_unsafe_links_and_limit_result_count(self):
        items = "".join(
            f"<item><title>Result {index}</title>"
            f"<link>{'javascript:alert(1)' if index == 0 else f'https://example.com/{index}'}</link>"
            "<description>Summary</description></item>"
            for index in range(8)
        )
        results = _parse_results(
            f"<rss><channel>{items}</channel></rss>".encode("utf-8")
        )
        self.assertEqual(len(results), 5)
        self.assertNotIn("javascript:", " ".join(item["url"] for item in results))

    def test_results_reject_xml_doctype(self):
        with self.assertRaisesRegex(RuntimeError, "غير آمن"):
            _parse_results(b'<!DOCTYPE rss [<!ENTITY x "expanded">]><rss/>')

    def test_search_rejects_empty_and_oversized_queries_before_network(self):
        with patch("web_research.urlopen") as urlopen:
            with self.assertRaises(ValueError):
                search_web("  ")
            with self.assertRaisesRegex(ValueError, str(MAX_QUERY_CHARS)):
                search_web("x" * (MAX_QUERY_CHARS + 1))
        urlopen.assert_not_called()

    def test_search_rejects_oversized_response_and_empty_results(self):
        with patch(
            "web_research.urlopen",
            return_value=io.BytesIO(b"x" * (MAX_RESPONSE_BYTES + 1)),
        ):
            with self.assertRaisesRegex(RuntimeError, "حجم الصفحة"):
                search_web("test")
        with patch("web_research.urlopen", return_value=io.BytesIO(b"<rss/>")):
            with self.assertRaisesRegex(RuntimeError, "لم يُرجع محرك البحث"):
                search_web("test")

    def test_search_surfaces_network_errors(self):
        with patch("web_research.urlopen", side_effect=URLError("offline")):
            with self.assertRaisesRegex(RuntimeError, "تعذر الاتصال"):
                search_web("test")

    def test_local_research_analysis_sends_only_bounded_web_excerpts(self):
        response = io.BytesIO(
            json.dumps({"message": {"content": "المقتطفات تشير إلى مصدرين."}}).encode()
        )
        results = [
            {
                "title": "Source title",
                "url": "https://example.com/report",
                "snippet": "Public summary",
                "private": "must not be sent",
            }
        ]
        with (
            patch.object(agent, "OLLAMA_URL", "http://127.0.0.1:11434"),
            patch.object(agent, "urlopen", return_value=response) as urlopen,
        ):
            analysis = agent.analyze_web_search_locally("security report", results)

        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        submitted = json.loads(payload["messages"][1]["content"])
        self.assertEqual(analysis, "المقتطفات تشير إلى مصدرين.")
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/api/chat")
        self.assertEqual(submitted["search_results"], [
            {
                "title": "Source title",
                "url": "https://example.com/report",
                "snippet": "Public summary",
            }
        ])
        self.assertIn("غير موثوقة", payload["messages"][0]["content"])

    def test_local_research_analysis_refuses_remote_ollama_endpoints(self):
        with (
            patch.object(agent, "OLLAMA_URL", "https://ollama.example.com"),
            patch.object(agent, "urlopen") as urlopen,
        ):
            with self.assertRaisesRegex(ValueError, "التحليل المحلي"):
                agent.analyze_web_search_locally(
                    "query",
                    [{"title": "title", "url": "https://example.com", "snippet": "text"}],
                )
        urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
