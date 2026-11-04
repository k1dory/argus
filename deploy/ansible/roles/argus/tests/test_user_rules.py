"""Правила движка: поставляемые — из образа, свои — каталог хоста (rc34, INC-5312).

Запуск из корня репозитория Python-интерпретатором окружения Ansible:
    python3 -m unittest discover -s deploy/ansible/roles/argus/tests -v
"""

from pathlib import Path
import unittest

import yaml


ROLE = Path(__file__).resolve().parents[1]
ROOT = ROLE.parents[3]
TASKS = yaml.safe_load((ROLE / "tasks/main.yml").read_text(encoding="utf-8"))
NAMES = [t.get("name", "") for t in TASKS]


def task(name):
    return next(t for t in TASKS if t.get("name") == name)


class UserRulesWiringTest(unittest.TestCase):
    def test_prod_engine_reads_shipped_rules_from_image_not_checkout(self):
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        engine = compose["services"]["engine"]
        self.assertEqual(engine["environment"]["RULES_DIR"], "/usr/share/argus/shipped/rules")
        self.assertEqual(engine["environment"]["RULES_USER_DIR"], "/etc/argus/rules.d")
        self.assertIn("${ARGUS_USER_RULES_DIR:-./rules.d}:/etc/argus/rules.d:ro", engine["volumes"])
        self.assertFalse([v for v in engine["volumes"] if str(v).startswith("./rules:")],
                         "rules/ checkout не монтируется в прод-движок")
        dockerfile = (ROOT / "engine/Dockerfile").read_text(encoding="utf-8")
        self.assertIn("COPY rules/ /usr/share/argus/shipped/rules/", dockerfile)
        self.assertIn("RULES_DIR=/usr/share/argus/shipped/rules", dockerfile)

    def test_dev_stand_keeps_checkout_rules(self):
        dev = yaml.safe_load((ROOT / "docker-compose.dev.yml").read_text(encoding="utf-8"))
        engine = dev["services"]["engine"]
        self.assertEqual(engine["environment"]["RULES_DIR"], "/rules")
        self.assertIn("./rules:/rules:ro", engine["volumes"])

    def test_role_creates_user_dir_and_points_env_after_init(self):
        idx = NAMES.index
        d = task("Правила: каталог своих правил")["ansible.builtin.file"]
        self.assertEqual((d["path"], d["state"], d["mode"]), ("{{ argus_user_rules_dir }}", "directory", "0755"))
        self.assertNotIn("when", task("Правила: каталог своих правил"), "каталог создаётся всегда, даже пустым")
        env = task(".env: каталог своих правил")["ansible.builtin.lineinfile"]
        self.assertEqual(env["line"], "ARGUS_USER_RULES_DIR={{ argus_user_rules_dir }}")
        self.assertNotIn("create", env, ".env создаёт только argus init")
        self.assertLess(idx(".env: секреты и состав стека (существующие значения не меняются)"),
                        idx(".env: каталог своих правил"))
        self.assertLess(idx(".env: каталог своих правил"), idx("Поднять стек"))
        sync = task("Правила: свои правила с управляющей машины")
        self.assertEqual(sync["when"], "argus_user_rules_src | length > 0")
        self.assertIn("--no-links", sync["ansible.posix.synchronize"]["rsync_opts"])


if __name__ == "__main__":
    unittest.main()
