"""Повторное ревью PR #20: обычный прогон показывает применённую миграцию.

Запуск: python3 -B -m unittest discover -s deploy/ansible/roles/argus/tests -v
Стенд test_migrations запускает default callback без -v и без внешних сервисов.
Ожидается исправленное поведение, без expectedFailure.
"""

import copy
import unittest
from unittest.mock import patch

import test_migrations as fixture


class MigrationStatusRegressionTest(unittest.TestCase):
    run_play = fixture.MigrationTasksTest.run_play

    def test_success_reports_last_applied_migration_without_verbose_mode(self):
        """P3: register сохраняет stdout, но default callback его не печатает."""
        start = next(
            index for index, task in enumerate(fixture.TASKS)
            if any(
                leaf.get("register") == "argus_migrations"
                for leaf in fixture.leaf_tasks([task])
            )
        )
        stop = next(
            index for index, task in enumerate(fixture.TASKS)
            if task.get("register") == "argus_ready"
        )
        self.assertLess(start, stop)
        # Включаем весь участок роли до HTTP readiness, чтобы будущая задача
        # debug без register тоже попала в тест. Сам YAML роли не изменяем.
        tasks = copy.deepcopy(fixture.TASKS[start:stop])
        with patch.object(fixture, "deployment_tasks", return_value=tasks):
            rc, output, calls = self.run_play({})
        self.assertEqual(rc, 0, output)
        self.assertEqual(calls.count("schema"), 1, output)
        self.assertEqual(calls.count("mutations"), 1, output)
        self.assertIn(
            "0031_events_source_last_projection.sql", output,
            "Успешная выкатка должна показать результат SELECT max(name), "
            "а не только имя успешно завершённой задачи",
        )


if __name__ == "__main__":
    unittest.main()
