"""Повторное ревью PR #20: секреты в диагностике не зависят от записи SQL.

Запуск тем же unittest discovery, что и job ansible (Linux, GNU sed):
    python3 -B -m unittest discover -s deploy/ansible/roles/argus/tests -v

Исполняются задачи роли через существующий стенд с заглушками make/docker.
Ожидается исправленное поведение, без expectedFailure. Все секреты фиктивные.
Проверять следует весь callback Ansible: no_log только на сборе лога не защищает
от его повторного вывода в ansible.builtin.fail.

Основание формата: ClickHouse v24.8.14.39-lts, Client::processError печатает
исходный query; ParserCreateUserQuery и ParserStringLiteral принимают пробелы,
переносы, SQL-экранирование и heredoc-литералы:
https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/programs/client/Client.cpp
https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Parsers/ExpressionElementParsers.cpp
"""

import unittest

import test_migrations as fixture


def dictionary_query(password_literal):
    # PASSWORD встречается и вне ALTER USER. Это только текст ошибки для
    # заглушки docker logs; SQL и соединение с источником не исполняются.
    return (
        "CREATE DICTIONARY qa (id UInt64) PRIMARY KEY id "
        "SOURCE(CLICKHOUSE(HOST 'localhost' PORT 9000 USER 'qa' "
        f"PASSWORD {password_literal} DB 'argus' TABLE 'qa')) "
        "LAYOUT(FLAT()) LIFETIME(0)"
    )


class MigrationLogRedactionRegressionTest(unittest.TestCase):
    # Используем стенд, не наследуя и не запуская повторно его базовые тесты.
    run_play = fixture.MigrationTasksTest.run_play

    def assert_credentials_hidden(self, cases, *, make_fails):
        # Хвост контейнера может содержать ошибки нескольких запусков migrator.
        # Префикс Compose сохраняется и на строках продолжения query.
        log = "\n".join(
            "migrator-1 | " + line
            for _, query, _ in cases
            for line in (
                "Code: 241. DB::Exception: MEMORY_LIMIT_EXCEEDED.\n"
                f"(query: {query})"
            ).splitlines()
        )
        self.assertLessEqual(len(log.splitlines()), 40)
        rc, output, calls = self.run_play(
            {
                "make_rc": 2 if make_fails else 0,
                "migrator_rc": 1,
                "migrator_log": log,
            },
            images="registry" if make_fails else "build",
        )
        self.assertNotEqual(rc, 0, "Ошибка migrator не должна стать успешной выкаткой")
        self.assertIn("make", calls, output)
        self.assertIn("logs", calls, output)
        self.assertNotIn("mutations", calls, output)
        self.assertIn("MEMORY_LIMIT_EXCEEDED", output, "Нужна безопасная причина отказа")
        for label, _, secrets in cases:
            for secret in secrets:
                with self.subTest(syntax=label, secret=secret):
                    self.assertNotIn(
                        secret, output,
                        "Секрет или его суффикс попал в итоговый callback Ansible",
                    )

    def test_control_single_line_authentication_forms_are_redacted(self):
        """Контроль: замена типа IDENTIFIED WITH сама по себе не обходит sed."""
        verifier, salt = "8a" * 32, "4c" * 16
        self.assert_credentials_hidden([
            (
                "sha256_hash",
                f"ALTER USER qa IDENTIFIED WITH sha256_hash BY '{verifier}' SALT '{salt}'",
                (verifier, salt),
            ),
            (
                "sha256_password",
                "ALTER USER qa IDENTIFIED WITH sha256_password BY 'qa-sha256-password'",
                ("qa-sha256-password",),
            ),
            (
                "plaintext_password",
                "ALTER USER qa IDENTIFIED WITH plaintext_password BY 'qa-plaintext-password'",
                ("qa-plaintext-password",),
            ),
            (
                "case_insensitive",
                "ALTER USER qa IDENTIFIED bY 'qa-mixed-case-password'",
                ("qa-mixed-case-password",),
            ),
            (
                "password_keyword",
                dictionary_query("'qa-dictionary-password'"),
                ("qa-dictionary-password",),
            ),
        ], make_fails=True)

    def test_make_deploy_failure_hides_multiline_and_tab_separated_credentials(self):
        """P2: пробел в regex не покрывает SQL whitespace и переносы строк."""
        verifier, salt = "6e" * 32, "5b" * 16
        self.assert_credentials_hidden([
            (
                "tab_after_by",
                "ALTER USER qa IDENTIFIED BY\t'qa-tab-password'",
                ("qa-tab-password",),
            ),
            (
                "newline_after_by_and_salt",
                f"ALTER USER qa IDENTIFIED WITH sha256_hash BY\n'{verifier}' SALT\n'{salt}'",
                (verifier, salt),
            ),
            (
                "newline_inside_password",
                "ALTER USER qa IDENTIFIED WITH plaintext_password BY 'prefix\nqa-newline-suffix'",
                ("qa-newline-suffix",),
            ),
            (
                "comment_after_by",
                "ALTER USER qa IDENTIFIED BY /* credential */ 'qa-comment-password'",
                ("qa-comment-password",),
            ),
            (
                "newline_after_password",
                dictionary_query("\n'qa-dictionary-newline-password'"),
                ("qa-dictionary-newline-password",),
            ),
        ], make_fails=True)

    def test_migration_check_failure_hides_escaped_and_alternative_string_literals(self):
        """P2: [^']* обрывается на экранированной кавычке; heredoc не совпадает."""
        self.assert_credentials_hidden([
            (
                "backslash_quote",
                "ALTER USER qa IDENTIFIED WITH plaintext_password BY 'prefix\\'qa-backslash-suffix'",
                ("qa-backslash-suffix",),
            ),
            (
                "doubled_quote",
                "ALTER USER qa IDENTIFIED WITH sha256_password BY 'prefix''qa-doubled-suffix'",
                ("qa-doubled-suffix",),
            ),
            (
                "heredoc",
                "ALTER USER qa IDENTIFIED BY $qa$qa-heredoc-password$qa$",
                ("qa-heredoc-password",),
            ),
            (
                "password_doubled_quote",
                dictionary_query("'prefix''qa-dictionary-quote-suffix'"),
                ("qa-dictionary-quote-suffix",),
            ),
        ], make_fails=False)


if __name__ == "__main__":
    unittest.main()
