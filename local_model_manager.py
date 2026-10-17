"""Bounded, loopback-only management for the supported Ollama models."""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


SUPPORTED_MODELS = ("qwen2.5:3b", "qwen3:4b")
MAX_MODEL_BYTES = 4 * 1024**3
MAX_MANIFEST_BYTES = 128 * 1024
REGISTRY_MANIFESTS = {
    "qwen2.5:3b": "https://registry.ollama.ai/v2/library/qwen2.5/manifests/3b",
    "qwen3:4b": "https://registry.ollama.ai/v2/library/qwen3/manifests/4b",
}


def _local_endpoint(base_url: str) -> str:
    endpoint = urlsplit(base_url)
    if (
        endpoint.scheme not in {"http", "https"}
        or endpoint.hostname not in {"localhost", "127.0.0.1", "::1"}
        or endpoint.username
        or endpoint.password
        or endpoint.query
        or endpoint.fragment
    ):
        raise ValueError("إدارة النماذج تتطلب عنوان Ollama محليًا (localhost أو loopback).")
    return base_url.rstrip("/")


def _validate_model(model: str) -> str:
    if model not in SUPPORTED_MODELS:
        raise ValueError("النموذج غير مدعوم؛ اختر اسمًا من قائمة نماذج NEXUS.")
    return model


def installed_models(base_url: str) -> list[str]:
    """Return exact installed model names from a local Ollama instance."""
    endpoint = _local_endpoint(base_url)
    try:
        with urlopen(f"{endpoint}/api/tags", timeout=5) as response:
            raw = response.read(1024 * 1024 + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"تعذر قراءة نماذج Ollama المحلية: {exc}") from exc
    if len(raw) > 1024 * 1024:
        raise RuntimeError("استجابة قائمة نماذج Ollama تجاوزت الحد الآمن.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"استجابة قائمة نماذج Ollama غير صالحة: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("استجابة Ollama لقائمة النماذج غير صالحة.")
    if not isinstance(payload, dict):
        raise RuntimeError("استجابة Ollama لقائمة النماذج غير صالحة.")
    models = payload.get("models", [])
    if not isinstance(models, list):
        raise RuntimeError("استجابة Ollama لقائمة النماذج غير صالحة.")
    return [
        model["name"]
        for model in models
        if isinstance(model, dict) and isinstance(model.get("name"), str)
    ]


def _verify_registry_size(model: str) -> int:
    request = Request(
        REGISTRY_MANIFESTS[model],
        headers={
            "Accept": (
                "application/vnd.docker.distribution.manifest.v2+json, "
                "application/vnd.oci.image.manifest.v1+json"
            )
        },
    )
    try:
        with urlopen(request, timeout=15) as response:
            raw = response.read(MAX_MANIFEST_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"تعذر التحقق من حجم النموذج في سجل Ollama الرسمي: {exc}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise RuntimeError("بيان النموذج أكبر من الحد الآمن.")
    try:
        layers = json.loads(raw.decode("utf-8")).get("layers")
        sizes = [layer["size"] for layer in layers]
    except (AttributeError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("بيان النموذج الرسمي غير صالح.") from exc
    if not sizes or any(type(size) is not int or size < 0 for size in sizes):
        raise RuntimeError("أحجام طبقات النموذج الرسمي غير صالحة.")
    total = sum(sizes)
    if total > MAX_MODEL_BYTES:
        raise RuntimeError("حجم النموذج يتجاوز حد التنزيل البالغ 4 GiB؛ أُلغي التنزيل.")
    return total


def pull_model(
    base_url: str,
    model: str,
    on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> None:
    """Pull one allowlisted model after checking its official manifest size."""
    endpoint = _local_endpoint(base_url)
    model = _validate_model(model)
    _verify_registry_size(model)

    request = Request(
        f"{endpoint}/api/pull",
        data=json.dumps({"name": model, "stream": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    totals_by_digest: Dict[str, int] = {}
    try:
        with urlopen(request, timeout=30) as response:
            while True:
                line = response.readline(64 * 1024 + 1)
                if not line:
                    break
                if len(line) > 64 * 1024:
                    raise RuntimeError("تجاوز تحديث تنزيل Ollama الحد الآمن لحجم السطر.")
                try:
                    update = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise RuntimeError("أرسل Ollama تحديث تنزيل غير صالح.") from exc
                if not isinstance(update, dict):
                    raise RuntimeError("أرسل Ollama تحديث تنزيل غير صالح.")
                if update.get("error"):
                    raise RuntimeError(str(update["error"])[:500])

                digest = update.get("digest")
                total = update.get("total")
                completed = update.get("completed")
                status = update.get("status")
                if not isinstance(status, str) or len(status) > 128:
                    raise RuntimeError("أرسل Ollama حالة تنزيل غير صالحة.")
                if "total" in update:
                    if (
                        not isinstance(digest, str)
                        or not digest
                        or len(digest) > 128
                        or type(total) is not int
                        or total < 0
                        or type(completed) is not int
                        or completed < 0
                    ):
                        raise RuntimeError("أرسل Ollama تقدم تنزيل غير صالح.")
                    if digest not in totals_by_digest and len(totals_by_digest) >= 128:
                        raise RuntimeError("تجاوز تنزيل Ollama عدد طبقات النموذج المسموح.")
                    if digest in totals_by_digest and totals_by_digest[digest] != total:
                        raise RuntimeError("تغيّر الحجم المعلن لطبقة تنزيل Ollama.")
                    totals_by_digest[digest] = total
                    if sum(totals_by_digest.values()) > MAX_MODEL_BYTES:
                        raise RuntimeError(
                            "تجاوز التنزيل حد 4 GiB المسموح؛ أُلغي تنزيل النموذج."
                        )
                if on_progress is not None:
                    on_progress(
                        {
                            "status": status,
                            "digest": digest[:128] if isinstance(digest, str) else "",
                            "completed": completed,
                            "total": total,
                        }
                    )
                if status == "success":
                    return
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"تعذر تنزيل النموذج عبر Ollama المحلي: {exc}") from exc
    raise RuntimeError("انقطع تنزيل Ollama قبل اكتماله.")


def persist_model_selection(model: str, env_path: Path) -> None:
    """Persist a supported model choice without changing other .env settings."""
    model = _validate_model(model)
    try:
        original = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
        lines = original.splitlines()
        output = []
        replaced = False
        for line in lines:
            key, separator, _value = line.partition("=")
            if separator and key.strip() == "AI_MODEL":
                if not replaced:
                    output.append(f"AI_MODEL={model}")
                    replaced = True
            else:
                output.append(line)
        if not replaced:
            output.append(f"AI_MODEL={model}")
        content = "\n".join(output).rstrip("\n") + "\n"
        env_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                newline="\n",
                dir=env_path.parent,
                delete=False,
            ) as temporary:
                temporary.write(content)
                temporary_path = temporary.name
            os.replace(temporary_path, env_path)
        finally:
            if temporary_path and os.path.exists(temporary_path):
                os.unlink(temporary_path)
    except OSError as exc:
        raise RuntimeError(f"تعذر حفظ اختيار النموذج في {env_path}: {exc}") from exc
