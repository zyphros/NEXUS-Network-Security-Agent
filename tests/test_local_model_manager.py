import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import local_model_manager as models


class LocalModelManagerTests(unittest.TestCase):
    def test_model_management_refuses_non_loopback_endpoint(self):
        with patch.object(models, "urlopen") as urlopen:
            with self.assertRaisesRegex(ValueError, "محليًا"):
                models.installed_models("https://ollama.example.com")
            with self.assertRaisesRegex(ValueError, "محليًا"):
                models.pull_model("http://192.0.2.10:11434", "qwen3:4b")
        urlopen.assert_not_called()

    def test_model_management_refuses_unlisted_model(self):
        with patch.object(models, "_verify_registry_size") as verify:
            with self.assertRaisesRegex(ValueError, "غير مدعوم"):
                models.pull_model("http://127.0.0.1:11434", "arbitrary:latest")
        verify.assert_not_called()

    def test_registry_size_is_summed_and_cannot_exceed_five_point_five_gb(self):
        manifest = io.BytesIO(
            json.dumps({"layers": [{"size": 20}, {"size": 30}]}).encode()
        )
        with patch.object(models, "urlopen", return_value=manifest):
            self.assertEqual(models._verify_registry_size("qwen3:4b"), 50)

        too_large = io.BytesIO(
            json.dumps({"layers": [{"size": models.MAX_MODEL_BYTES + 1}]}).encode()
        )
        with patch.object(models, "urlopen", return_value=too_large):
            with self.assertRaisesRegex(RuntimeError, "5.5 GB"):
                models._verify_registry_size("qwen3:4b")

    def test_qwen3_eight_billion_parameter_model_fits_download_limit(self):
        self.assertIn("qwen3:8b", models.SUPPORTED_MODELS)
        self.assertEqual(
            models.REGISTRY_MANIFESTS["qwen3:8b"],
            "https://registry.ollama.ai/v2/library/qwen3/manifests/8b",
        )
        manifest = io.BytesIO(
            json.dumps({"layers": [{"size": 5_225_387_677}]}).encode()
        )
        with patch.object(models, "urlopen", return_value=manifest):
            self.assertEqual(
                models._verify_registry_size("qwen3:8b"), 5_225_387_677
            )

    def test_pull_uses_only_local_ollama_api_and_reports_progress(self):
        stream = io.BytesIO(
            b'{"status":"downloading","digest":"sha256:abc","total":100,"completed":40}\n'
            b'{"status":"success"}\n'
        )
        progress = []
        with (
            patch.object(models, "urlopen", return_value=stream) as urlopen,
            patch.object(models, "_verify_registry_size", return_value=100),
        ):
            models.pull_model(
                "http://127.0.0.1:11434", "qwen3:4b", progress.append
            )

        pull_request = urlopen.call_args_list[0].args[0]
        self.assertEqual(pull_request.full_url, "http://127.0.0.1:11434/api/pull")
        self.assertEqual(
            json.loads(pull_request.data.decode("utf-8")),
            {"name": "qwen3:4b", "stream": True},
        )
        self.assertEqual(len(progress), 2)

    def test_pull_rejects_streamed_layers_over_five_point_five_gb(self):
        stream = io.BytesIO(
            json.dumps(
                {
                    "status": "downloading",
                    "digest": "sha256:oversized",
                    "total": models.MAX_MODEL_BYTES + 1,
                    "completed": 0,
                }
            ).encode()
            + b"\n"
        )
        with (
            patch.object(models, "urlopen", return_value=stream),
            patch.object(models, "_verify_registry_size", return_value=100),
        ):
            with self.assertRaisesRegex(RuntimeError, "5.5 GB"):
                models.pull_model("http://127.0.0.1:11434", "qwen3:4b")

    def test_installed_model_names_are_returned(self):
        response = io.BytesIO(
            json.dumps(
                {"models": [{"name": "qwen3:4b"}, {"name": "other:model"}]}
            ).encode()
        )
        with patch.object(models, "urlopen", return_value=response):
            self.assertEqual(
                models.installed_models("http://localhost:11434"),
                ["qwen3:4b", "other:model"],
            )

        malformed = io.BytesIO(b"[]")
        with patch.object(models, "urlopen", return_value=malformed):
            with self.assertRaisesRegex(RuntimeError, "غير صالحة"):
                models.installed_models("http://localhost:11434")

    def test_model_selection_persists_without_replacing_other_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / ".env"
            env_path.write_text(
                "AI_ENABLED=true\nAI_MODEL = qwen2.5:3b\nOLLAMA_URL=http://localhost:11434\n",
                encoding="utf-8",
            )
            models.persist_model_selection("qwen3:4b", env_path)
            self.assertEqual(
                env_path.read_text(encoding="utf-8"),
                "AI_ENABLED=true\nAI_MODEL=qwen3:4b\nOLLAMA_URL=http://localhost:11434\n",
            )
            with self.assertRaisesRegex(ValueError, "غير مدعوم"):
                models.persist_model_selection("unknown:model", env_path)



if __name__ == "__main__":
    unittest.main()
