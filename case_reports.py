"""Helpers for exporting user-requested NEXUS case summaries."""

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def build_case_report(
    sample_name: str,
    static_report: str,
    ai_analysis: str = "",
    alerts: Optional[List[Dict[str, Any]]] = None,
    security_events: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope_note": (
            "Advisory triage only; indicators are not a verdict. "
            "The selected sample was not executed."
        ),
        "sample_name": sample_name[:240],
        "static_report": static_report[:20_000],
        "local_ai_analysis": ai_analysis[:20_000],
        "recent_alerts": [dict(item) for item in (alerts or [])[-20:]],
        "recent_security_events": [
            dict(item) for item in (security_events or [])[-20:]
        ],
    }


def render_case_html(report: Dict[str, Any]) -> str:
    serialized = json.dumps(report, ensure_ascii=False, indent=2)
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>NEXUS case report</title>"
        "<style>body{font:15px system-ui,sans-serif;max-width:1000px;"
        "margin:2rem auto;padding:0 1rem;background:#07111f;color:#e6f0fa}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0d1a2b;"
        "padding:1rem;border-radius:.5rem}</style></head><body>"
        "<h1>NEXUS local security case report</h1><pre>"
        + html.escape(serialized)
        + "</pre></body></html>\n"
    )
