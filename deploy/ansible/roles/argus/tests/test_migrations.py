"""Регрессии PR #20; ожидают исправленного поведения, без expectedFailure.

Запуск из корня репозитория Python-интерпретатором окружения Ansible
(ansible-core, PyYAML и Jinja2 уже должны быть установлены):
    python3 -m unittest discover -s deploy/ansible/roles/argus/tests -v

Исполняются настоящие задачи роли и стандартный callback Ansible. make/docker
заменены локальными заглушками; Docker daemon, ClickHouse, SSH и .env не нужны.
Запускать в изолированном тестовом окружении. Таймаут subprocess — страховка
тестового стенда, а НЕ ограничение времени, предоставляемое проверяемой ролью.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

from jinja2 import Environment, StrictUndefined
import yaml


ROLE = Path(__file__).resolve().parents[1]
ROOT = ROLE.parents[3]
TASKS = yaml.safe_load((ROLE / "tasks/main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
DEPLOY_REGISTERS = {"argus_up", "argus_deploy", "argus_migrations", "argus_mutations"}
STATUS_TASKS = yaml.safe_load((ROLE / "tasks/migrator_status.yml").read_text(encoding="utf-8"))
CONTAINER_ID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
DEFAULT_STATUS = {
    "exit": 0, "stage": "done", "file": "", "last_applied": "0031_events_source_last_projection.sql",
    "code": None, "name": "", "weak_vars": [], "run": CONTAINER_ID[:12],
}


def leaf_tasks(tasks, inherited=None):
    """Учитывать ограничения, унаследованные от block/rescue/always."""
    inherited = inherited or {}
    for task in tasks:
        effective = {**inherited, **task}
        if any(key in task for key in ("block", "rescue", "always")):
            controls = {
                key: effective[key]
                for key in ("timeout", "async", "poll", "no_log")
                if key in effective
            }
            for key in ("block", "rescue", "always"):
                yield from leaf_tasks(task.get(key, []), controls)
        else:
            yield effective


def task_for(register):
    matches = [task for task in leaf_tasks(TASKS) if task.get("register") == register]
    if len(matches) != 1:
        raise AssertionError(f"Ожидалась одна задача с register={register}, найдено {len(matches)}")
    return matches[0]


def deployment_tasks():
    # Сохраняем порядок, условия отказа, block/rescue/always и no_log из роли.
    # Подготовку хоста и readiness HTTP намеренно не запускаем.
    return copy.deepcopy([
        task for task in TASKS
        if any(leaf.get("register") in DEPLOY_REGISTERS for leaf in leaf_tasks([task]))
    ])


CLI_STUB = r'''
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["ARGUS_TEST_STATE"])
state = json.loads((root / "state.json").read_text())
args = sys.argv[1:]
tool = Path(sys.argv[0]).name

def record(kind):
    with (root / "calls.jsonl").open("a") as stream:
        stream.write(json.dumps({"kind": kind, "args": args}) + "\n")

if tool == "make" and args in (["up"], ["deploy"]):
    record("make")
    if state.get("make_rc", 0):
        print('service "migrator" did not complete successfully: exit 1', file=sys.stderr)
    else:
        print("Started")
    sys.exit(state.get("make_rc", 0))
if tool == "docker":
    if args[:2] == ["compose", "ps"]:
        record("ps")
        print("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        sys.exit(0)
    if args[:1] == ["inspect"]:
        record("inspect")
        print(state.get("migrator_rc", 0))
        sys.exit(0)
    if args[:2] == ["compose", "logs"]:
        record("logs")
        print(state.get("migrator_log", "migrate: done"))
        sys.exit(0)
    if args[:2] == ["compose", "exec"]:
        query = sys.stdin.read()
        if "system.mutations" in query:
            record("mutations")
            counter = root / "mutation-count"
            index = int(counter.read_text()) if counter.exists() else 0
            counter.write_text(str(index + 1))
            rows = state.get("mutations", ["0|0|"])
            print(rows[min(index, len(rows) - 1)])
            sys.exit(state.get("query_rc", 0))
        if "schema_migrations" in query:
            record("schema")
            print("0031_events_source_last_projection.sql")
            sys.exit(0)
record("unsupported")
print("UNSUPPORTED FIXTURE COMMAND: " + repr([tool, *args]), file=sys.stderr)
sys.exit(99)
'''


class MigrationTasksTest(unittest.TestCase):
    def run_play(self, state, *, images="build", start_at=None, registers=None):
        """Только localhost, пустое окружение, временные HOME/cache/config."""
        with tempfile.TemporaryDirectory(prefix="argus-migrations-test-") as directory:
            work = Path(directory)
            for name in ("bin", "home", "tmp", "local", "remote", "async", "collections"):
                (work / name).mkdir(mode=0o700)
            (work / "state.json").write_text(json.dumps(state), encoding="utf-8")
            # Статус migrate.sh (run/migrator/migrate.json) и общий файл задач роли рядом
            # с плейбуком — include_tasks ищет его относительно плейбука.
            (work / "run" / "migrator").mkdir(parents=True)
            status = state.get("status_raw")
            if status is None:
                # Компактно, как write_status в migrate.sh (printf без пробелов).
                status = json.dumps({**DEFAULT_STATUS, **state.get("status", {})}, separators=(",", ":"))
            if status != "":
                (work / "run" / "migrator" / "migrate.json").write_text(status, encoding="utf-8")
            (work / "migrator_status.yml").write_text(
                (ROLE / "tasks/migrator_status.yml").read_text(encoding="utf-8"), encoding="utf-8")
            (work / "VERSION").write_text("regression-fixture\n", encoding="utf-8")
            for tool in ("docker", "make"):
                script = work / "bin" / tool
                script.write_text(f"#!{sys.executable}\n" + CLI_STUB, encoding="utf-8")
                script.chmod(0o700)

            config = work / "ansible.cfg"
            config.write_text(
                "[defaults]\nstdout_callback=default\nretry_files_enabled=False\n"
                "host_key_checking=False\nforks=1\ntask_timeout=0\n",
                encoding="utf-8",
            )
            env = {
                "PATH": f"{work / 'bin'}:/usr/bin:/bin",
                "HOME": str(work / "home"),
                "TMPDIR": str(work / "tmp"),
                "XDG_CACHE_HOME": str(work / "home" / "cache"),
                "LANG": "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "ANSIBLE_CONFIG": str(config),
                "ANSIBLE_LOCAL_TEMP": str(work / "local"),
                "ANSIBLE_REMOTE_TEMP": str(work / "remote"),
                "ANSIBLE_COLLECTIONS_PATH": str(work / "collections"),
                "ANSIBLE_NOCOLOR": "1",
                "ARGUS_TEST_STATE": str(work),
            }
            variables = {
                **DEFAULTS,
                "argus_dir": str(work),
                "argus_images": images,
                "argus_up_timeout_sec": 10,
                "argus_mutations_retries": 2,
                "argus_mutations_delay_sec": 0,
                "argus_sync": {"stdout_lines": []},
                "argus_git": {"changed": False},
                "ansible_python_interpreter": sys.executable,
                "ansible_remote_tmp": str(work / "remote"),
                "ansible_async_dir": str(work / "async"),
            }
            selected = deployment_tasks()
            if registers is not None:
                selected = [
                    task for task in selected
                    if any(leaf.get("register") in registers for leaf in leaf_tasks([task]))
                ]
            # Сократить только интервал опроса make, без изменения его failure path.
            def shorten_poll(tasks):
                for task in tasks:
                    if task.get("register") in {"argus_up", "argus_deploy"}:
                        task["poll"] = 1
                    for key in ("block", "rescue", "always"):
                        shorten_poll(task.get(key, []))
            shorten_poll(selected)
            play = [{
                "name": "ARGUS migration regression",
                "hosts": "localhost",
                "connection": "local",
                "gather_facts": False,
                "become": False,
                "vars": variables,
                "environment": env,
                "tasks": selected,
            }]
            playbook = work / "play.yml"
            playbook.write_text(yaml.safe_dump(play, allow_unicode=True), encoding="utf-8")
            command = [
                sys.executable, "-B", "-m", "ansible.cli.playbook",
                "-i", "localhost,", str(playbook),
            ]
            if start_at:
                command.extend(["--start-at-task", start_at])
            with subprocess.Popen(
                command, cwd=work, env=env, text=True, encoding="utf-8",
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
            ) as process:
                try:
                    output, _ = process.communicate(timeout=40)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
                    self.fail("Тестовый playbook превысил страховочный лимит 40 секунд")
                finally:
                    # Остановить оставшихся потомков в группе процесса Ansible.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                returncode = process.returncode
            calls_path = work / "calls.jsonl"
            calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
            self.assertNotIn("unsupported", [call["kind"] for call in calls], output)
            return returncode, output, [call["kind"] for call in calls]

    def test_migration_probes_have_an_enforced_action_timeout(self):
        """P2: retries/delay не прерывают зависший docker exec/inspect/ps.

        Контракт требует положительный Ansible timeout либо async с poll,
        ограничивающий целиком действие, в том числе обращение к Docker daemon.
        Таймаут только clickhouse-client этого свойства не обеспечивает.
        """
        renderer = Environment(undefined=StrictUndefined)

        def seconds(value):
            return float(renderer.from_string(str(value)).render(DEFAULTS))

        probes = {
            "argus_migrator_container": next(t for t in STATUS_TASKS if t.get("register") == "argus_migrator_container"),
            "argus_mutations": task_for("argus_mutations"),
        }
        for register, task in probes.items():
            with self.subTest(register=register):
                action_timeout = seconds(task.get("timeout", 0))
                async_timeout = seconds(task.get("async", 0))
                poll = seconds(task.get("poll", 15))
                self.assertTrue(
                    action_timeout > 0 or (async_timeout > 0 and poll > 0),
                    f"{register}: нет ограничения длительности одной попытки; "
                    "retries и delay начинают действовать только после возврата команды",
                )

    def test_failed_migrator_is_diagnosed_after_make_failure(self):
        """P2: диагностическая ветка должна работать при штатном отказе up."""
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        self.assertEqual(
            compose["services"]["engine"]["depends_on"]["migrator"]["condition"],
            "service_completed_successfully",
        )
        for images in ("build", "registry"):
            with self.subTest(images=images):
                rc, output, calls = self.run_play({
                    "make_rc": 2,
                    "migrator_rc": 1,
                    "status": {"exit": 1, "stage": "migrations", "file": "0031_events_source_last_projection.sql",
                               "last_applied": "0030_search_text_index.sql", "code": 241, "name": "MEMORY_LIMIT_EXCEEDED"},
                }, images=images)
                self.assertIn("make", calls, output)
                self.assertNotEqual(rc, 0, "Ошибка миграции не должна становиться успешным деплоем")
                self.assertIn("0031_events_source_last_projection.sql", output, "диагностика из статуса migrate.sh")
                self.assertIn("MEMORY_LIMIT_EXCEEDED", output)
                self.assertNotIn("logs", calls, "лог migrator не читается вовсе")
                self.assertNotIn("mutations", calls, "После отказа migrator нельзя продолжать ожидание мутаций")

    def test_resumed_diagnostics_do_not_disclose_clickhouse_password_verifier(self):
        """P2: --start-at-task достигает ветки с логом упавшего ALTER USER.

        migrate.sh передаёт хеш и соль в SQL; Client::processError в ClickHouse
        24.8 выводит исходный query без маскирования. Здесь только фиктивные
        значения; проверяется настоящий stdout callback Ansible.
        Источник формата: ClickHouse/ClickHouse v24.8.14.39-lts,
        programs/client/Client.cpp, Client::processError.
        """
        dummy_password = "qa-only-password-never-used"
        salt = "7c" * 16
        verifier = hashlib.sha256((dummy_password + salt).encode()).hexdigest()
        migration = (ROOT / "scripts/migrate.sh").read_text(encoding="utf-8")
        self.assertIn("IDENTIFIED WITH sha256_hash BY '$hash' SALT '$salt'", migration)
        fixture_log = (
            "Received exception from server (version 24.8):\n"
            "Code: 76. DB::Exception: Cannot write access entity: No space left on device.\n"
            f"(query: ALTER USER argus_console IDENTIFIED WITH sha256_hash BY '{verifier}' SALT '{salt}')"
        )
        rc, output, calls = self.run_play({
            "migrator_rc": 1,
            "migrator_log": fixture_log,
            "status": {"exit": 1, "stage": "users", "code": 76, "name": "CANNOT_WRITE_ACCESS_ENTITY"},
        }, start_at=task_for("argus_migrations")["name"])
        self.assertNotIn("logs", calls, "лог migrator не читается вовсе")
        self.assertNotEqual(rc, 0, output)
        self.assertNotIn(verifier, output, "Хеш пароля ClickHouse попал в stdout Ansible")
        self.assertNotIn(salt, output, "Соль пароля ClickHouse попала в stdout Ansible")

    def test_completed_mutations_are_unchanged_on_each_run(self):
        """Контроль: повторное чтение готового состояния успешно и unchanged."""
        for _ in range(2):
            rc, output, calls = self.run_play({}, registers={"argus_migrations", "argus_mutations"})
            self.assertEqual(rc, 0, output)
            self.assertEqual(calls.count("mutations"), 1, output)
            self.assertRegex(output, r"changed=0\b")

    def test_pending_mutation_is_retried_until_done(self):
        rc, output, calls = self.run_play(
            {"mutations": ["1|8|", "0|0|"]}, registers={"argus_mutations"},
        )
        self.assertEqual(rc, 0, output)
        self.assertEqual(calls.count("mutations"), 2, output)

    def test_failed_mutation_stops_on_first_result(self):
        rc, output, calls = self.run_play(
            {"mutations": ["1|8|events: MEMORY_LIMIT_EXCEEDED"]}, registers={"argus_mutations"},
        )
        self.assertNotEqual(rc, 0, output)
        self.assertEqual(calls.count("mutations"), 1, output)

    def test_pending_mutation_exhausts_finite_retries(self):
        rc, output, calls = self.run_play(
            {"mutations": ["1|8|"]}, registers={"argus_mutations"},
        )
        self.assertNotEqual(rc, 0, output)
        # retries=2 означает исходную попытку плюс два повтора.
        self.assertEqual(calls.count("mutations"), 3, output)


if __name__ == "__main__":
    unittest.main()
