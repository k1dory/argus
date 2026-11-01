"""Снимок правил движка (rc34, INC-5312): обновление checkout не меняет правила
под ещё работающим старым движком.

Запуск из корня репозитория Python-интерпретатором окружения Ansible:
    python3 -m unittest discover -s deploy/ansible/roles/argus/tests -v

Исполняются настоящие команды задач роли (cmd после рендера Jinja) в bash во
временном каталоге; Docker и Ansible не нужны.
"""

from pathlib import Path
import os
import subprocess
import tempfile
import time
import unittest

from jinja2 import Environment, StrictUndefined
import yaml


ROLE = Path(__file__).resolve().parents[1]
ROOT = ROLE.parents[3]
TASKS = yaml.safe_load((ROLE / "tasks/main.yml").read_text(encoding="utf-8"))
NAMES = [t.get("name", "") for t in TASKS]
SNAPSHOT = "Правила: снимок для движка"
ENV_TASK = ".env: снимок правил движка"
PRUNE = "Правила: старые снимки"


def task(name):
    return next(t for t in TASKS if t.get("name") == name)


def render(template, **variables):
    env = Environment(undefined=StrictUndefined)
    env.filters["quote"] = lambda s: "'" + str(s).replace("'", "'\"'\"'") + "'"
    return env.from_string(template).render(**variables)


class RulesSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.checkout = self.root / "argus"
        self.releases = self.root / "releases"
        (self.checkout / "rules" / "ops").mkdir(parents=True)
        (self.checkout / "rules" / "ops" / "skew.yml").write_text("group_by: attrs.peer\n", encoding="utf-8")
        (self.checkout / "rules" / "a.yml").write_text("id: a\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def run_task(self, name, **extra):
        cmd = render(task(name)["ansible.builtin.shell"]["cmd"], argus_dir=str(self.checkout),
                     argus_rules_releases_dir=str(self.releases), argus_rules_keep=2, **extra)
        out = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=60, check=True)
        return out.stdout.strip()

    def snapshot(self):
        out = self.run_task(SNAPSHOT)
        state, path = out.split()[0], out.split()[-1]
        return state, Path(path)

    def test_same_content_reuses_snapshot_and_changed_content_leaves_old_intact(self):
        state, first = self.snapshot()
        self.assertEqual(state, "created")
        self.assertEqual((first / "ops" / "skew.yml").read_text(encoding="utf-8"), "group_by: attrs.peer\n")
        state, again = self.snapshot()
        self.assertEqual((state, again), ("exists", first), "тот же rules/ — тот же снимок, движок не пересоздаётся")

        # Код обновился: правило в checkout изменилось, а старый движок смонтировал first.
        (self.checkout / "rules" / "ops" / "skew.yml").write_text(
            "group_by: attrs.peer, attrs.source\ngroup_by_previous: attrs.peer\n", encoding="utf-8")
        state, second = self.snapshot()
        self.assertEqual(state, "created")
        self.assertNotEqual(second, first)
        self.assertEqual((first / "ops" / "skew.yml").read_text(encoding="utf-8"), "group_by: attrs.peer\n",
                         "снимок старой версии неизменен: старый движок не видит правила новой")
        self.assertIn("group_by_previous", (second / "ops" / "skew.yml").read_text(encoding="utf-8"))

    def test_file_rename_changes_snapshot(self):
        _, first = self.snapshot()
        (self.checkout / "rules" / "a.yml").rename(self.checkout / "rules" / "b.yml")
        _, second = self.snapshot()
        self.assertNotEqual(first, second, "хеш учитывает имена файлов, не только содержимое")

    def test_prune_keeps_current_and_newest(self):
        made = []
        for i in range(5):
            (self.checkout / "rules" / "a.yml").write_text(f"id: a{i}\n", encoding="utf-8")
            _, path = self.snapshot()
            made.append(path)
            past = time.time() - (10 - i) * 60
            os.utime(path, (past, past))
        current = made[1]  # выкатили не самый новый (откат): он должен остаться
        self.run_task(PRUNE, argus_rules_snapshot={"stdout": f"exists {current}"})
        left = sorted(p.name for p in self.releases.iterdir())
        self.assertEqual(left, sorted({current.name, made[4].name, made[3].name}))


class RulesSnapshotWiringTest(unittest.TestCase):
    def test_compose_mounts_snapshot_with_checkout_fallback(self):
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        self.assertIn("${ARGUS_RULES_HOST_DIR:-./rules}:/rules:ro", compose["services"]["engine"]["volumes"])

    def test_order_snapshot_after_code_env_after_init_prune_after_deploy(self):
        idx = NAMES.index
        self.assertLess(idx("Исполняемые биты скриптов"), idx(SNAPSHOT), "снимок — из уже обновлённого кода")
        self.assertLess(idx(".env: секреты и состав стека (существующие значения не меняются)"), idx(ENV_TASK),
                        ".env пишется после argus init: иначе init принял бы неполный .env за готовый")
        self.assertLess(idx(ENV_TASK), idx("Поднять стек"), "путь снимка — до пересоздания движка")
        self.assertLess(idx("Дождаться коллектора"), idx(PRUNE), "старые снимки — только после успешной выкатки")
        env = task(ENV_TASK)["ansible.builtin.lineinfile"]
        self.assertNotIn("create", env, ".env создаёт только argus init")
        self.assertNotIn("when", task(ENV_TASK), "и для build, и для registry")


if __name__ == "__main__":
    unittest.main()
