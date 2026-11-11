"""Cron бэкапа: ротация и резерв из инвентаря попадают в окружение backup.sh.

11.11.2026 на argus1 полные копии за 14 дней заполнили диск, а срок хранения
задавался только в .env хоста. Пустые переменные роли не перебивают .env,
мусор не доходит до строки cron (assert), а не превращается в 0.

Запуск из корня репозитория Python-интерпретатором окружения Ansible:
    python3 -m unittest discover -s deploy/ansible/roles/argus/tests -v
"""

from pathlib import Path
import unittest

import yaml
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar

ROLE = Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load((ROLE / "tasks/main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text(encoding="utf-8"))
NAMES = [t.get("name", "") for t in TASKS]


def task(name):
    return next(t for t in TASKS if t.get("name") == name)


def templar(**overrides):
    return Templar(loader=DataLoader(), variables={**DEFAULTS, "argus_dir": "/opt/argus", **overrides})


def job(**overrides):
    return templar(**overrides).template(task("Резервные копии по cron")["ansible.builtin.cron"]["job"])


def assert_ok(**overrides):
    t = templar(**overrides)
    conds = task("Резервные копии — проверка ротации и резерва")["ansible.builtin.assert"]["that"]
    return all(t.template("{{ %s }}" % c) for c in conds)


class BackupCronTest(unittest.TestCase):
    def test_defaults_leave_dotenv_in_charge(self):
        self.assertTrue(assert_ok())
        self.assertEqual(job(), "cd /opt/argus && ./scripts/backup.sh >> /var/log/argus-backup.log 2>&1")

    def test_inventory_values_reach_script(self):
        self.assertTrue(assert_ok(argus_backup_keep_days=2, argus_backup_reserve_mb="20480"))
        self.assertEqual(
            job(argus_backup_keep_days=2, argus_backup_reserve_mb="20480"),
            "cd /opt/argus && BACKUP_KEEP_DAYS=2 BACKUP_RESERVE_MB=20480 "
            "./scripts/backup.sh >> /var/log/argus-backup.log 2>&1",
        )

    def test_garbage_and_zero_rejected_before_cron(self):
        for bad in ("2; rm -rf /", "0", "7d", "-1", "08", "2\n", "\n", "2\r\n", " 2"):
            self.assertFalse(assert_ok(argus_backup_keep_days=bad), repr(bad))
        for bad in ("10G", "01024", "20480\n", "\n", "99999999"):
            self.assertFalse(assert_ok(argus_backup_reserve_mb=bad), repr(bad))
        self.assertTrue(assert_ok(argus_backup_keep_days="9999", argus_backup_reserve_mb="0"))
        self.assertLess(NAMES.index("Резервные копии — проверка ротации и резерва"),
                        NAMES.index("Резервные копии по cron"))


if __name__ == "__main__":
    unittest.main()
