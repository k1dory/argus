"""Статус migrator в роли argus — только из run/migrator/migrate.json.

Замена регрессий redaction/allowlist/status (PR #20, #31): лог migrator не читается
вовсе, поэтому любые строки SQL и исключений (ALTER USER с хешем и солью, throwIf,
многострочные литералы, поддельные «migrate: …») на вывод не влияют. Проверяется
одно свойство: в выводе Ansible нет ничего, кроме проверенных полей статуса.
Запуск: python3 -B -m unittest discover -s deploy/ansible/roles/argus/tests -v
"""

import hashlib
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import test_migrations as fixture

SECRET_LOG_LINES = [
    "Code: 76. DB::Exception: Cannot write access entity. (query: ALTER USER argus_console "
    "IDENTIFIED WITH sha256_hash BY '{verifier}' SALT '{salt}')",
    "Code: 395. DB::Exception: qa-only-throwif-token. (FUNCTION_THROW_IF_VALUE_IS_NON_ZERO)",
    "migrate: apply 9999_qa-only-filename-token.sql",
    "migrate: ОТКАЗ qa-only-refusal-token",
]


class MigratorStatusJsonTest(unittest.TestCase):
    run_play = fixture.MigrationTasksTest.run_play

    def secrets_log(self):
        salt = "7c" * 16
        verifier = hashlib.sha256(("qa-only-password" + salt).encode()).hexdigest()
        log = "\n".join(line.format(verifier=verifier, salt=salt) for line in SECRET_LOG_LINES)
        return log, [verifier, salt, "qa-only-throwif-token", "qa-only-filename-token", "qa-only-refusal-token"]

    def test_failure_output_is_status_fields_only(self):
        log, secrets = self.secrets_log()
        for make_fails in (True, False):
            with self.subTest(make_fails=make_fails):
                rc, output, calls = self.run_play({
                    "make_rc": 2 if make_fails else 0,
                    "migrator_rc": 76,
                    "migrator_log": log,
                    "status": {"exit": 76, "stage": "users", "file": "", "code": 76,
                               "name": "CANNOT_WRITE_ACCESS_ENTITY"},
                }, images="registry" if make_fails else "build")
                self.assertNotEqual(rc, 0, output)
                self.assertNotIn("logs", calls, "лог migrator не читается")
                for secret in secrets:
                    self.assertNotIn(secret, output)
                for field in ("код выхода 76", "этап users", "ClickHouse код 76 (CANNOT_WRITE_ACCESS_ENTITY)"):
                    self.assertIn(field, output)

    def test_tampered_status_fields_are_dropped(self):
        """Статус не той формы (подмена, кавычки, пробелы в полях) не разбирается вовсе."""
        bad = "qa-only-tampered-token' (query: ALTER USER x BY 'secret')"
        rc, output, calls = self.run_play({
            "migrator_rc": 1,
            "status": {"exit": 1, "stage": "migrations", "file": bad, "last_applied": bad,
                       "code": bad, "name": bad, "weak_vars": [bad, "CLICKHOUSE_RO_PASSWORD"]},
        })
        self.assertNotEqual(rc, 0, output)
        self.assertNotIn("qa-only-tampered-token", output)
        self.assertNotIn("secret", output)
        self.assertIn("статуса этого запуска нет", output)

    def test_garbage_or_missing_status_is_reported_without_content(self):
        for raw in ("not json qa-only-garbage-token", "", '["qa-only-array-token"]'):
            with self.subTest(raw=raw[:12]):
                rc, output, calls = self.run_play({"migrator_rc": 1, "status_raw": raw})
                self.assertNotEqual(rc, 0, output)
                self.assertNotIn("qa-only-", output)
                self.assertIn("статуса этого запуска нет", output)

    def test_stale_status_from_previous_run_is_not_trusted(self):
        rc, output, calls = self.run_play({"status": {"run": "fedcba987654"}})
        self.assertNotEqual(rc, 0, "успех прошлого запуска не подтверждает текущий")
        self.assertIn("статуса этого запуска нет", output)

    def test_weak_password_refusal_names_variables(self):
        rc, output, calls = self.run_play({"migrator_rc": 1, "status": {
            "exit": 1, "stage": "check", "last_applied": "", "weak_vars": ["CLICKHOUSE_RO_PASSWORD"]}})
        self.assertNotEqual(rc, 0, output)
        self.assertIn("дефолтные пароли: CLICKHOUSE_RO_PASSWORD", output)

    def test_success_reports_last_applied_without_verbose(self):
        rc, output, calls = self.run_play({}, registers={"argus_migrations", "argus_mutations"})
        self.assertEqual(rc, 0, output)
        self.assertIn("последняя применённая 0031_events_source_last_projection.sql", output)
        self.assertNotIn("logs", calls)


class MigrateShStatusFormatTest(unittest.TestCase):
    """Формат write_status из настоящего scripts/migrate.sh принимается ролью."""
    run_play = fixture.MigrationTasksTest.run_play

    def test_written_status_is_accepted_by_role(self):
        script = (fixture.ROOT / "scripts/migrate.sh").read_text(encoding="utf-8")
        funcs = re.search(r"^safe\(\) .*?^}\n", script, re.S | re.M)
        write = re.search(r"^write_status\(\) \{.*?^}\n", script, re.S | re.M)
        self.assertTrue(funcs and write, "safe() и write_status() найдены в migrate.sh")
        with tempfile.TemporaryDirectory() as d:
            body = (
                funcs.group(0) + write.group(0)
                + 'stage="done" current="" last="0034_incidents_group_key.sql" fail_code=""\n'
                + "weak_vars=()\nHOST=x ADMIN_USER=x\nwrite_status 0\n"
            )
            env = {"PATH": "/usr/bin:/bin", "STATUS_DIR": d, "HOSTNAME": fixture.CONTAINER_ID[:12]}
            subprocess.run(["bash", "-c", "STATUS_DIR=$STATUS_DIR\n" + body], env=env, check=True)
            text = (Path(d) / "migrate.json").read_text(encoding="utf-8")
        rc, output, calls = self.run_play({"status_raw": text}, registers={"argus_migrations"})
        self.assertEqual(rc, 0, output)
        self.assertIn("последняя применённая 0034_incidents_group_key.sql", output)


if __name__ == "__main__":
    unittest.main()
