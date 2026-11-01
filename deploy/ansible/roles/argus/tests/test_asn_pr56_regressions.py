"""PR #56: ASN role regressions; no cron daemon or deployed host is accessed.

Run with the existing role runner:
    python3 -m unittest discover -s deploy/ansible/roles/argus/tests -p 'test_asn_pr56_regressions.py' -v
"""

from pathlib import Path
import shlex
import unittest

from jinja2 import Environment, StrictUndefined
import yaml


ROLE = Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load((ROLE / "tasks/main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text(encoding="utf-8"))


def asn_cron():
    return next(
        task["ansible.builtin.cron"]
        for task in TASKS
        if task.get("ansible.builtin.cron", {}).get("name") == "argus asn update"
    )


def render(value, **overrides):
    renderer = Environment(undefined=StrictUndefined)
    renderer.filters["quote"] = shlex.quote
    return renderer.from_string(value).render({**DEFAULTS, **overrides})


def cron_command(job):
    """Vixie cron splits at unescaped %, before the shell parses quotes.

    https://manpages.debian.org/bookworm/cron/crontab.5.en.html
    A backslash protecting % is removed before passing the command to sh.
    """
    command = []
    i = 0
    while i < len(job):
        if job[i] == "%":
            return "".join(command), job[i + 1:]
        if job[i] == "\\" and i + 1 < len(job):
            if job[i + 1] == "%":
                command.append("%")
            else:
                command.extend(job[i:i + 2])
            i += 2
            continue
        command.append(job[i])
        i += 1
    return "".join(command), ""


class ASNRolePR56Test(unittest.TestCase):
    def test_cron_preserves_percent_encoded_source_url(self):
        # The initial command task accepts this URL, but shell quoting alone
        # cannot preserve it in crontab. Mirrors and signed URLs can contain %.
        url = "https://mirror.invalid/ASN%20daily.tsv.gz?signature=dummy%2Fvalue"
        job = render(asn_cron()["job"], argus_asn=True, argus_asn_url=url)
        command, stdin = cron_command(job)
        self.assertEqual(
            stdin, "",
            "cron truncates the configured ASN URL at % and sends the rest to stdin: " + command,
        )
        self.assertIn(url, shlex.split(command), "cron must fetch the same URL as the initial task")

    def test_default_cron_and_disable_transition(self):
        cron = asn_cron()
        self.assertEqual(render(cron["state"], argus_asn=True), "present")
        self.assertEqual(render(cron["state"], argus_asn=False), "absent")
        command, stdin = cron_command(render(cron["job"], argus_asn=True))
        self.assertEqual(stdin, "")
        self.assertIn(DEFAULTS["argus_asn_url"], shlex.split(command))


if __name__ == "__main__":
    unittest.main()
