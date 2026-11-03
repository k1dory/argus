"""PR #102: regression contracts for the rules snapshot role.

Run with the existing Ansible-role runner (Python with Jinja2 and PyYAML):
    python3 -m unittest discover -s deploy/ansible/roles/argus/tests \
        -p 'test_rules_snapshot_pr102_regressions.py' -v

These tests execute the role's rendered shell commands against disposable files.
They need no Docker daemon, Ansible inventory, root privileges, or network.
Command wrappers only inject failures or coordinate concurrent publishers; the
snapshot and pruning algorithms are always read from tasks/main.yml.
"""

import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

from test_rules_snapshot import ENV_TASK, PRUNE, SNAPSHOT, render, task


class RulesSnapshotPR102RegressionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="argus-pr102-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.checkout = self.root / "checkout"
        self.rules = self.checkout / "rules"
        self.releases = self.root / "releases"
        (self.rules / "ops").mkdir(parents=True)
        self.original = "id: original\n"
        (self.rules / "a.yml").write_text(self.original, encoding="utf-8")
        (self.rules / "ops" / "b.yml").write_text("id: other\n", encoding="utf-8")
        # Source permissions must not depend on the test runner's umask.
        for directory in (self.checkout, self.rules, self.rules / "ops"):
            directory.chmod(0o755)
        for path in self.rules.rglob("*.yml"):
            path.chmod(0o644)
        for directory in (self.root / "home", self.root / "tmp"):
            directory.mkdir()
        self.environment = {
            "PATH": os.defpath,
            "HOME": str(self.root / "home"),
            "TMPDIR": str(self.root / "tmp"),
            "LC_ALL": "C",
            "LANG": "C",
        }

    def command(self, name, **overrides):
        variables = {
            "argus_dir": str(self.checkout),
            "argus_rules_releases_dir": str(self.releases),
            "argus_rules_keep": 2,
            **overrides,
        }
        return render(task(name)["ansible.builtin.shell"]["cmd"], **variables)

    @staticmethod
    def stop_process(process):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.communicate(timeout=5)

    def start_task(self, name=SNAPSHOT, *, tools=None, umask=0o022, **overrides):
        environment = dict(self.environment)
        if tools is not None:
            environment["PATH"] = str(tools) + os.pathsep + environment["PATH"]
        process = subprocess.Popen(
            ["/bin/bash", "-c", self.command(name, **overrides)],
            cwd=self.root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            umask=umask,
        )
        self.addCleanup(self.stop_process, process)
        return process

    @staticmethod
    def finish(process):
        stdout, stderr = process.communicate(timeout=20)
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    def run_task(self, name=SNAPSHOT, **kwargs):
        return self.finish(self.start_task(name, **kwargs))

    def snapshot_path(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        state, separator, value = result.stdout.strip().partition(" ")
        self.assertIn(state, ("created", "exists"), result.stdout)
        self.assertEqual(separator, " ", result.stdout)
        path = Path(value)
        self.assertTrue(path.is_dir(), result.stdout)
        return path

    def published_snapshots(self):
        # An aborted copy may leave staging directories, but never a final
        # rules-<hex digest> directory that subsequent runs could reuse.
        return [path for path in self.releases.glob("rules-*")
                if re.fullmatch(r"rules-[0-9a-f]+", path.name)]

    def wrapper(self, directory, name, body):
        directory.mkdir(exist_ok=True)
        path = directory / name
        path.write_text("#!" + sys.executable + "\n" + textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o755)
        return directory

    def gated_command(self, directory, command, reached, release):
        real = shutil.which(command, path=os.defpath)
        self.assertIsNotNone(real, command + " is required by the role")
        return self.wrapper(directory, command, f"""
            import os
            from pathlib import Path
            import sys
            import time

            Path({str(reached)!r}).touch()
            deadline = time.monotonic() + 15
            while not Path({str(release)!r}).exists():
                if time.monotonic() >= deadline:
                    raise SystemExit("test gate timed out")
                time.sleep(0.01)
            os.execv({real!r}, [{real!r}, *sys.argv[1:]])
        """)

    @staticmethod
    def await_marker(marker, process, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if marker.exists():
                return True
            if process.poll() is not None:
                return False
            time.sleep(0.01)
        return marker.exists()

    @staticmethod
    def file_tree(directory):
        return {
            str(path.relative_to(directory)): path.read_bytes()
            for path in directory.rglob("*") if path.is_file()
        }

    def test_concurrent_same_hash_publish_does_not_mutate_published_tree(self):
        # A has copied its tree but has not renamed it. B has already passed
        # the existence check, but is paused before clearing the shared .tmp.
        # Publish A, then allow B to finish. Ordinary `mv tmp existing-dir`
        # nests tmp inside the directory that A has already made mountable.
        a_ready, a_go = self.root / "a-ready", self.root / "a-go"
        b_ready, b_go = self.root / "b-ready", self.root / "b-go"
        a_tools = self.gated_command(self.root / "a-tools", "mv", a_ready, a_go)
        b_tools = self.gated_command(self.root / "b-tools", "rm", b_ready, b_go)
        expected = self.file_tree(self.rules)

        first = self.start_task(tools=a_tools)
        self.assertTrue(self.await_marker(a_ready, first), "first publisher did not reach mv")
        second = self.start_task(tools=b_tools)
        # A serialized implementation can legitimately keep B waiting for A's
        # lock. Release A after this bounded wait in that case as well.
        self.await_marker(b_ready, second)
        a_go.touch()
        published = self.snapshot_path(self.finish(first))
        self.assertEqual(self.file_tree(published), expected)
        b_go.touch()
        second_result = self.finish(second)

        self.assertEqual(
            self.file_tree(published), expected,
            "a second publisher changed an already published snapshot; its nested "
            ".tmp directory is also traversed by engine/internal/rules.Files",
        )
        self.assertEqual(self.snapshot_path(second_result), published)

    def test_checkout_change_between_hash_and_copy_does_not_poison_rollback(self):
        # An overlapping checkout update lands after hashing but before cp.
        # A later rollback must not reuse newer bytes under the old hash.
        real_cp = shutil.which("cp", path=os.defpath)
        self.assertIsNotNone(real_cp)
        tools = self.wrapper(self.root / "changing-copy", "cp", f"""
            import os
            from pathlib import Path
            import sys

            Path({str(self.rules / 'a.yml')!r}).write_text("id: newer\\n", encoding="utf-8")
            os.execv({real_cp!r}, [{real_cp!r}, *sys.argv[1:]])
        """)
        raced = self.run_task(tools=tools)
        self.assertEqual((self.rules / "a.yml").read_text(encoding="utf-8"), "id: newer\n",
                         "the injected checkout update did not run")
        if raced.returncode != 0:
            # Detecting concurrent mutation and refusing publication is safe.
            self.assertFalse(self.published_snapshots())
            return
        self.snapshot_path(raced)
        (self.rules / "a.yml").write_text(self.original, encoding="utf-8")
        rolled_back = self.snapshot_path(self.run_task())
        self.assertEqual(
            (rolled_back / "a.yml").read_text(encoding="utf-8"), self.original,
            "rollback reused newer rule bytes cached under the old checkout's hash",
        )

    def test_file_hash_failure_aborts_before_publication(self):
        # One per-file hash fails; later files and the final manifest hash still
        # succeed. Every inner failure must propagate out of the substitution.
        tools = self.wrapper(self.root / "failing-hash", "sha256sum", """
            import hashlib
            import os
            import stat
            import sys

            data = sys.stdin.buffer.read()
            if stat.S_ISREG(os.fstat(0).st_mode) and data.startswith(b"id: original"):
                print("injected per-file hash failure", file=sys.stderr)
                raise SystemExit(74)
            print(hashlib.sha256(data).hexdigest() + "  -")
        """)
        result = self.run_task(tools=tools)
        self.assertIn("injected per-file hash failure", result.stderr)
        self.assertNotEqual(result.returncode, 0, "a failed hash must abort deployment")
        self.assertFalse(self.published_snapshots(), "failed hashes must not enter the cache")

    def test_symlink_retarget_does_not_reuse_old_rules(self):
        # Both payloads are regular files and remain unchanged. Only the link
        # read by rules.LoadFile changes; find -type f does not hash that link.
        (self.rules / "first.data").write_text("id: first\n", encoding="utf-8")
        (self.rules / "second.data").write_text("id: second\n", encoding="utf-8")
        link = self.rules / "selected.yml"
        link.symlink_to("first.data")
        first_result = self.run_task()
        if first_result.returncode != 0:
            # Rejecting symlinks explicitly is an alternative valid policy.
            self.assertRegex(first_result.stdout + first_result.stderr, r"(?i)symlink|symbolic|regular|симлин|ссылк")
            self.assertFalse(self.published_snapshots())
            return
        first = self.snapshot_path(first_result)
        link.unlink()
        link.symlink_to("second.data")
        second = self.snapshot_path(self.run_task())
        self.assertEqual(
            (second / "selected.yml").read_text(encoding="utf-8"), "id: second\n",
            "retargeting a rule symlink must not silently keep the old selected rule",
        )
        self.assertNotEqual(first, second)
        self.assertEqual((first / "selected.yml").read_text(encoding="utf-8"), "id: first\n")

    def test_restrictive_umask_keeps_snapshot_readable_by_nonroot_engine(self):
        # Ansible becomes root; engine/Dockerfile uses distroless :nonroot.
        # The host's umask must not turn readable source files into root-only
        # files in the bind mount. No uid change or privileged mount is needed.
        snapshot = self.snapshot_path(self.run_task(umask=0o077))
        for path in (snapshot, *snapshot.rglob("*")):
            with self.subTest(path=str(path.relative_to(snapshot))):
                permissions = stat.S_IMODE(path.stat().st_mode)
                required = 0o005 if path.is_dir() else 0o004
                self.assertEqual(
                    permissions & required, required,
                    f"nonroot engine cannot read/traverse {path.name}: mode {permissions:04o}",
                )

    def test_env_preserves_snapshot_directory_with_spaces(self):
        self.releases = self.root / "rule snapshots"
        result = self.run_task()
        snapshot = self.snapshot_path(result)
        line = render(
            task(ENV_TASK)["ansible.builtin.lineinfile"]["line"],
            argus_rules_snapshot={"stdout": result.stdout.strip()},
        )
        # Accept either a literal path or dotenv quoting for this path (which
        # deliberately has no $/#/backslash). Do not split stdout on whitespace.
        key, separator, value = line.partition("=")
        self.assertEqual((key, separator), ("ARGUS_RULES_HOST_DIR", "="))
        if value.startswith(("'", '"')):
            value, = shlex.split(value)
        self.assertEqual(value, str(snapshot), ".env must point at the snapshot actually created")

    def test_delayed_prune_does_not_delete_snapshot_selected_by_parallel_rollback(self):
        # A has deployed the newest snapshot and is paused before pruning.
        # B rolls back to an older snapshot and updates .env/Compose, but has
        # not pruned yet. A then resumes with its obsolete registered stdout.
        snapshots = []
        for index in range(4):
            (self.rules / "a.yml").write_text(f"id: release-{index}\n", encoding="utf-8")
            snapshot = self.snapshot_path(self.run_task())
            os.utime(snapshot, (1700000000 + index, 1700000000 + index))
            snapshots.append(snapshot)
        active, obsolete_current = snapshots[0], snapshots[-1]
        line = render(
            task(ENV_TASK)["ansible.builtin.lineinfile"]["line"],
            argus_rules_snapshot={"stdout": f"exists {active}"},
        )
        (self.checkout / ".env").write_text(line + "\n", encoding="utf-8")
        result = self.run_task(
            PRUNE, argus_rules_snapshot={"stdout": f"created {obsolete_current}"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (active / "a.yml").is_file(),
            "late pruning removed the selected rules; :ro only protects against "
            "container writes, and the engine can reload the emptied mounted tree",
        )

    def test_sequential_rollback_and_pruning_keep_current_plus_two(self):
        # Control: ordinary sequential rollback works, including when its
        # snapshot is older than the two retained non-current snapshots.
        snapshots = []
        for index in range(5):
            (self.rules / "a.yml").write_text(f"id: release-{index}\n", encoding="utf-8")
            snapshot = self.snapshot_path(self.run_task())
            os.utime(snapshot, (1700000000 + index, 1700000000 + index))
            snapshots.append(snapshot)
        (self.rules / "a.yml").write_text("id: release-0\n", encoding="utf-8")
        rollback = self.run_task()
        self.assertEqual(self.snapshot_path(rollback), snapshots[0])
        pruned = self.run_task(PRUNE, argus_rules_snapshot={"stdout": rollback.stdout.strip()})
        self.assertEqual(pruned.returncode, 0, pruned.stderr)
        self.assertEqual(set(self.releases.iterdir()), {snapshots[0], snapshots[-1], snapshots[-2]})
        self.assertEqual((snapshots[0] / "a.yml").read_text(encoding="utf-8"), "id: release-0\n")


if __name__ == "__main__":
    unittest.main()
