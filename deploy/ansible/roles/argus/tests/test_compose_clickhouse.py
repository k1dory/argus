"""ClickHouse в compose: без временного init-сервера entrypoint (e2e «unhealthy»).

С CLICKHOUSE_DB entrypoint образа на пустом томе поднимает временный сервер под
пользователем clickhouse и гасит его kill от root; без CAP_KILL (cap_drop: ALL)
это «Operation not permitted», контейнер перезапускается, и compose видел
сервис unhealthy через 1–2 с после старта. Базу создаёт migrator.
"""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[5]


class ClickHouseInitTest(unittest.TestCase):
    def test_no_entrypoint_init_server_without_kill_capability(self):
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        ch = compose["services"]["clickhouse"]
        caps = set(ch.get("cap_add", []))
        if "ALL" in ch.get("cap_drop", []) and "KILL" not in caps:
            self.assertNotIn("CLICKHOUSE_DB", ch.get("environment", {}),
                             "CLICKHOUSE_DB включает init-сервер entrypoint, которому без CAP_KILL нечем его погасить")
            volumes = [str(v) for v in ch.get("volumes", [])]
            self.assertFalse([v for v in volumes if "docker-entrypoint-initdb.d" in v],
                             "initdb-скрипты тоже запускают временный сервер")

    def test_migrator_creates_database(self):
        migrate = (ROOT / "scripts/migrate.sh").read_text(encoding="utf-8")
        self.assertIn("CREATE DATABASE IF NOT EXISTS argus", migrate)


if __name__ == "__main__":
    unittest.main()
