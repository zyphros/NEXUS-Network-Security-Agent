"""Safe, allowlisted commands and advisory isolation guidance for the dashboard."""

from typing import Any, Dict, Optional


_COMMAND_ALIASES = {
    "help": {"help", "/help", "مساعدة", "الأوامر"},
    "status": {"status", "/status", "الحالة", "حالة"},
    "alerts": {"alerts", "/alerts", "التنبيهات", "التنبيهات الأخيرة"},
    "connections": {"connections", "/connections", "الاتصالات"},
    "recommendations": {
        "recommendations",
        "/recommendations",
        "اقتراحات",
        "التوصيات",
        "توصيات العزل",
    },
    "start": {"start", "start monitoring", "ابدأ", "ابدأ المراقبة"},
    "stop": {"stop", "stop monitoring", "أوقف", "أوقف المراقبة", "إيقاف المراقبة"},
    "reports": {"reports", "open reports", "التقارير", "فتح التقارير"},
}
_COMMANDS = {
    alias: command
    for command, aliases in _COMMAND_ALIASES.items()
    for alias in aliases
}


def parse_command(text: str) -> Optional[str]:
    """Return an allowlisted in-app command; never interpret shell syntax."""
    return _COMMANDS.get(" ".join(text.casefold().split()))


def isolation_recommendation(event: Dict[str, Any]) -> str:
    """Describe cautious, human-reviewed next steps without changing system state."""
    alerts = event.get("alerts", [])
    alerts = [alert for alert in alerts if isinstance(alert, dict)] if isinstance(alerts, list) else []
    security_events = event.get("security_events", [])
    has_external_event = isinstance(security_events, list) and bool(security_events)
    process_names = sorted(
        {
            alert["rule"].split(":", 1)[1][:80]
            for alert in alerts
            if isinstance(alert.get("rule"), str)
            and alert["rule"].startswith("many_connections:")
        }
    )

    if process_names:
        processes = ", ".join(process_names)
        guidance = (
            f"العملية {processes} تجاوزت حد الاتصالات. تحقّق يدويًا من PID ومسار الملف "
            "والناشر/التوقيع ومبرر الاتصالات، ثم راجع التنبيه في سياقه."
        )
    elif has_external_event:
        guidance = (
            "راجع الحدث الأصلي في Wazuh أو مصدر Syslog وتحقق من الجهاز والقاعدة "
            "والتوقيت والسياق قبل اتخاذ قرار."
        )
    elif alerts:
        guidance = (
            "قارن عدد الاتصالات والوجهات بعمل الجهاز المعتاد، وحدد العملية المالكة "
            "للروابط قبل اعتبارها ضارة."
        )
    else:
        guidance = "لا يوجد تنبيه حديث؛ ابدأ المراقبة واجمع سياقًا قبل تقييم أي اتصال."

    return (
        f"{guidance} إذا تأكد الاشتباه، فاتبع إجراء الاستجابة المعتمد لديك وبموافقة "
        "المسؤول، مثل العزل عبر أداة حماية مُدارة. NEXUS لا يعزل العمليات أو الأجهزة "
        "ولا يحظر الاتصالات أو يغيّر إعدادات النظام."
    )
