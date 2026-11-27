import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]


class SessionEnvironmentTest(unittest.TestCase):
    def test_compose_forwards_session_policy(self):
        docker = shutil.which("docker")
        if docker is None or subprocess.run([docker, "compose", "version"], capture_output=True).returncode != 0:
            self.skipTest("Docker Compose v2 is required")
        expected = {
            "ARGUS_SESSION_IDLE_HOURS": "0.05",
            "ARGUS_SESSION_MAX_HOURS": "2",
            "ARGUS_SSO_SESSION_MAX_HOURS": "1",
        }
        compose = ROOT / "docker-compose.yml"
        required = re.findall(
            r"\$\{([A-Z][A-Z0-9_]*):\?",
            compose.read_text(encoding="utf-8"),
        )
        values = {key: "fixture-only-" + "x" * 32 for key in required}
        values.update(expected)
        with tempfile.TemporaryDirectory(prefix="argus-session-env-") as tmp:
            dotenv = Path(tmp) / "review.env"
            dotenv.write_text(
                "".join(f"{key}={value}\n" for key, value in values.items()),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    docker, "compose", "--env-file", str(dotenv),
                    "-f", str(compose), "config", "--format", "json",
                ],
                cwd=ROOT,
                # DOCKER_CONFIG не подменяем: в нём лежит плагин compose (cli-plugins).
                env={
                    "PATH": os.environ.get("PATH", os.defpath),
                    "HOME": os.environ.get("HOME", tmp),
                },
                capture_output=True,
                text=True,
                timeout=20,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = json.loads(result.stdout)["services"]["web"]["environment"]
        for key, value in expected.items():
            with self.subTest(variable=key):
                self.assertEqual(actual.get(key), value)


if __name__ == "__main__":
    unittest.main()
