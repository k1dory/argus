"""Третий круг PR #20: границы белого списка лога migrator.

Запуск в изолированном окружении с уже установленными зависимостями Ansible:
    python3 -B -m unittest discover -s deploy/ansible/roles/argus/tests -v

Используется существующий стенд: настоящий YAML роли и default callback Ansible,
локальные заглушки make/docker, только фиктивные секреты. SQL не исполняется.
Тесты ожидают защищённого поведения; expectedFailure/skip для дефектов нет.

Формат входных данных основан на ClickHouse v24.8.14.39-lts:
* src/Functions/throwIf.cpp, FunctionThrowIf::execute: custom_message передаётся
  в Exception::createRuntime без добавления кавычек и без замены переносов;
* programs/client/Client.cpp, Client::processError: исключение и исходный query
  печатаются отдельно, включая физические строки внутри SQL-литерала.
https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Functions/throwIf.cpp
https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/programs/client/Client.cpp

Контроль с ASCII-разделителями выполняет именно shell-команду роли, включая
awk -v sq="'", на системном awk: mawk в окружении Debian/Ubuntu или BSD awk
на macOS. Алгоритм фильтрации в Python не дублируется.
"""

import unittest

import test_migrations as fixture


class MigrationAllowlistRegressionTest(unittest.TestCase):
    run_play = fixture.MigrationTasksTest.run_play

    def assert_safe_rescue(self, log, secrets, *, make_fails=False,
                           prefix="migrator-1 | "):
        # Compose добавляет префикс к каждой физической строке, включая
        # продолжения исключений и SQL. В stdout Ansible этот префикс не нужен.
        prefixed = "\n".join(prefix + line for line in log.splitlines())
        rc, output, calls = self.run_play({
            "make_rc": 2 if make_fails else 0,
            "migrator_rc": 1,
            "migrator_log": prefixed,
        }, images="registry" if make_fails else "build")

        self.assertNotEqual(rc, 0, "Ошибка migrator должна прервать выкатку")
        self.assertIn("make", calls, output)
        self.assertIn("logs", calls, output)
        self.assertNotIn("mutations", calls, output)
        self.assertIn("migrator: код 1", output,
                      "Фильтр должен сохранить безопасную диагностику")
        if prefix:
            self.assertNotIn(prefix.rstrip(), output,
                             "Префикс Compose остался в диагностике")
        for secret in secrets:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, output,
                                 "Содержимое закрытого лога попало в callback Ansible")
        return output

    def test_exception_message_without_quotes_does_not_disclose_secret(self):
        """P2: отсутствие разделителя не делает текст DB::Exception безопасным."""
        secret = "qa-only-unquoted-exception-token"
        output = self.assert_safe_rescue(
            "Received exception from server (version 24.8):\n"
            f"Code: 395. DB::Exception: {secret}. "
            "(FUNCTION_THROW_IF_VALUE_IS_NON_ZERO)\n"
            f"(query: SELECT throwIf(1, '{secret}'))",
            [secret],
        )
        self.assertIn("Code: 395", output)

    def test_unicode_quotes_in_exception_message_do_not_disclose_secret(self):
        """Тот же P2: типографские кавычки — текст сообщения, не SQL-синтаксис."""
        cases = [
            ("«", "»", "qa-only-guillemet-token"),
            ("“", "”", "qa-only-curly-double-token"),
            ("‘", "’", "qa-only-curly-single-token"),
        ]
        # throwIf принимает обычную строку, которая может содержать эти символы.
        # Не предполагаем, что ClickHouse принимает Unicode-кавычки вместо SQL '.
        log = "\n".join(
            f"Code: 395. DB::Exception: {left}{secret}{right}. "
            "(FUNCTION_THROW_IF_VALUE_IS_NON_ZERO)\n"
            f"(query: SELECT throwIf(1, '{left}{secret}{right}'))"
            for left, right, secret in cases
        )
        output = self.assert_safe_rescue(
            log, [secret for _, _, secret in cases], make_fails=True,
        )
        self.assertIn("Code: 395", output)

    def test_sql_literal_continuations_cannot_impersonate_migrator_records(self):
        """P2: каждая строка SQL заново проходит whitelist без контекста query."""
        secrets = [
            "qa-only-query-apply-token",
            "qa-only-query-refusal-token",
            "qa-only-query-code-token",
        ]
        # Корректный многострочный SQL-литерал пароля. При отказе ALTER USER
        # клиент выводит исходный query; это не сообщения самого migrate.sh.
        query = (
            "ALTER USER qa IDENTIFIED WITH plaintext_password BY 'prefix\n"
            f"migrate: apply 9999_{secrets[0]}.sql\n"
            f"migrate: ОТКАЗ {secrets[1]}\n"
            f"Code: 395. DB::Exception: {secrets[2]}\n"
            "suffix'"
        )
        output = self.assert_safe_rescue(
            "migrate: apply 0031_events_source_last_projection.sql\n"
            "Code: 76. DB::Exception: Cannot write access entity.\n"
            f"(query: {query})",
            secrets, make_fails=True,
        )
        self.assertIn("Code: 76", output)

    def test_exception_continuations_cannot_impersonate_migrator_records(self):
        """Тот же P2 возникает до (query:), внутри многострочного исключения."""
        secrets = [
            "qa-only-exception-apply-token",
            "qa-only-exception-refusal-token",
            "qa-only-exception-code-token",
        ]
        # Пользовательское сообщение throwIf может включать реальные переносы.
        # Усечение первой строки на ASCII-кавычке не защищает следующие строки.
        output = self.assert_safe_rescue(
            "Code: 395. DB::Exception: 'message begins\n"
            f"migrate: apply 9999_{secrets[0]}.sql\n"
            f"migrate: ОТКАЗ '{secrets[1]}'\n"
            f"Code: 395. DB::Exception: {secrets[2]}\n"
            "message ends'. (FUNCTION_THROW_IF_VALUE_IS_NON_ZERO)",
            secrets,
        )
        self.assertIn("Code: 395", output)

    def test_migration_filename_is_not_an_unrestricted_public_log_field(self):
        """Тот же P2: ветка apply копирует весь basename, включая литералы."""
        secret = "qa-only-filename-token"
        # scripts/migrate.sh:63-70 обходит *.sql и печатает basename без проверки.
        # Такой basename допустим на ФС и попадает в apply ещё до выполнения SQL.
        self.assert_safe_rescue(
            f"migrate: apply 0035_password='{secret}'.sql\n"
            "Code: 241. DB::Exception: Memory limit exceeded.",
            [secret], make_fails=True,
        )

    def test_control_ascii_delimiters_and_compose_prefixes(self):
        """Контроль: -v передаёт апостроф; снимается только префикс Compose."""
        cases = [
            ("'", "qa-only-ascii-single-token"),
            ('"', "qa-only-ascii-double-token"),
            ("`", "qa-only-backtick-token"),
            ("$", "qa-only-dollar-token"),
            ("(query:", "qa-only-query-suffix-token"),
        ]
        # Ровно пять исключений: все должны попасть в диагностический хвост,
        # поэтому успешное скрытие нельзя объяснить ограничением последних пяти.
        log = "\n".join([
            "migrate: apply 0031_events_source_last_projection.sql",
            "migrate: ОТКАЗ — дефолтные пароли в CLICKHOUSE_PASSWORD.",
            *(
                "Code: 241. DB::Exception: Memory limit exceeded "
                f"| diagnostic {delimiter}{secret}"
                for delimiter, secret in cases
            ),
        ])
        for prefix in ("migrator-1 | ", "argus-migrator-1  | "):
            with self.subTest(prefix=prefix):
                output = self.assert_safe_rescue(
                    log, [secret for _, secret in cases], prefix=prefix,
                )
                self.assertIn("0031_events_source_last_projection.sql", output)
                self.assertIn("migrate: ОТКАЗ", output)
                self.assertIn("Code: 241", output)


if __name__ == "__main__":
    unittest.main()
