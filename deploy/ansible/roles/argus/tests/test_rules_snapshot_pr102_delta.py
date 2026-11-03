"""Review of 223830a..HEAD: snapshot ownership and publication regressions.

Run in an isolated test environment, with the role's existing dependencies:
    python3 -B -m unittest discover -s deploy/ansible/roles/argus/tests \
        -p 'test_rules_snapshot_pr102_delta.py' -v

The tests assert the required behavior, without expectedFailure. Shell commands
come from tasks/main.yml and run with /bin/bash (including macOS Bash 3.2).
Docker is a fixture for pruning. The three dotenv checks require a Compose CLI,
use only `compose config`, and explicitly point it at a nonexistent socket.
No container, image pull, deployed host, or real .env is used.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

import yaml

import test_rules_snapshot as role
import test_rules_snapshot_pr102_regressions as fixtures


class RulesSnapshotPR102DeltaTest(unittest.TestCase):
    def setUp(self):
        # Reuse fixtures without inheriting/re-running the earlier test cases.
        self.fixture = fixtures.RulesSnapshotPR102RegressionTest()
        self.fixture.addCleanup = self.addCleanup
        self.fixture.setUp()

    def seed_releases(self, count=6):
        """Valid snapshot names with deterministic retention order."""
        f = self.fixture
        f.releases.mkdir(exist_ok=True)
        releases = []
        for index in range(count):
            path = f.releases / f"rules-{index + 1:016x}"
            path.mkdir(exist_ok=True)
            (path / "a.yml").write_text(f"id: release-{index}\n", encoding="utf-8")
            os.utime(path, (1700000000 + index, 1700000000 + index))
            releases.append(path)
        return releases

    def write_env(self, snapshot):
        f = self.fixture
        line = role.render(
            role.task(role.ENV_TASK)["ansible.builtin.lineinfile"]["line"],
            argus_rules_snapshot={"stdout": f"exists {snapshot}"},
        )
        # lineinfile normally replaces the destination atomically. Reproduce
        # that property, not a partially written .env.
        temporary = f.checkout / ".env.next"
        temporary.write_text(line + "\n", encoding="utf-8")
        temporary.replace(f.checkout / ".env")

    def docker_fixture(self, mounted, fail_at=None):
        f = self.fixture
        mount_state = f.root / "mounted-snapshot"
        mount_state.write_text(str(mounted), encoding="utf-8")
        calls = f.root / "docker-calls"
        calls.write_text("", encoding="utf-8")
        directory = f.wrapper(f.root / "docker-tools", "docker", f"""
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            if args == ["compose", "ps", "-q", "engine"]:
                operation = "ps"
            elif (len(args) == 4 and args[:2] == ["inspect", "-f"]
                  and args[-1] == "fixture-engine"):
                operation = "inspect"
            else:
                raise SystemExit("unexpected Docker call: " + repr(args))
            with Path({str(calls)!r}).open("a", encoding="utf-8") as stream:
                stream.write(operation + "\\n")
            if operation == {fail_at!r}:
                print("injected Docker inspection failure", file=sys.stderr)
                raise SystemExit(74)
            if operation == "ps":
                print("fixture-engine")
            else:
                print(Path({str(mount_state)!r}).read_text(encoding="utf-8"))
        """)
        return directory, mount_state, calls

    def test_stale_observation_cannot_remove_replacement_owners_lock(self):
        # A reads an abandoned lock's age. Before A's rmdir, B reclaims it and
        # acquires a FRESH lock. B is then held immediately before publication.
        # A must wait for B; otherwise its rename makes B's later mv nest a
        # .stage directory inside an already published immutable snapshot.
        f = self.fixture
        f.releases.mkdir()
        lock = f.releases / ".lock"
        lock.mkdir()
        os.utime(lock, (946684800, 946684800))
        stale_read, a_go = f.root / "stale-read", f.root / "a-go"
        a_copy = f.root / "a-copy"
        b_ready, b_go = f.root / "b-ready", f.root / "b-go"
        real_find = shutil.which("find", path=os.defpath)
        real_cp = shutil.which("cp", path=os.defpath)
        self.assertIsNotNone(real_find)
        self.assertIsNotNone(real_cp)
        a_tools = f.wrapper(f.root / "a-tools", "find", f"""
            import os
            from pathlib import Path
            import subprocess
            import sys
            import time

            args = sys.argv[1:]
            if args and args[0] == {str(lock)!r} and "-mmin" in args:
                result = subprocess.run([{real_find!r}, *args], capture_output=True)
                if result.stdout and not Path({str(stale_read)!r}).exists():
                    Path({str(stale_read)!r}).touch()
                    deadline = time.monotonic() + 15
                    while not Path({str(a_go)!r}).exists():
                        if time.monotonic() >= deadline:
                            raise SystemExit("stale observation gate timed out")
                        time.sleep(0.01)
                # Return the actual observation made BEFORE B replaced .lock.
                sys.stdout.buffer.write(result.stdout)
                sys.stderr.buffer.write(result.stderr)
                raise SystemExit(result.returncode)
            os.execv({real_find!r}, [{real_find!r}, *args])
        """)
        f.wrapper(a_tools, "cp", f"""
            import os
            from pathlib import Path
            import sys

            Path({str(a_copy)!r}).touch()
            os.execv({real_cp!r}, [{real_cp!r}, *sys.argv[1:]])
        """)
        b_tools = f.gated_command(f.root / "b-tools", "mv", b_ready, b_go)
        expected = f.file_tree(f.rules)

        first = f.start_task(tools=a_tools)
        self.assertTrue(f.await_marker(stale_read, first), "A did not inspect the stale lock")
        second = f.start_task(tools=b_tools)
        self.assertTrue(f.await_marker(b_ready, second), "B did not acquire a fresh lock")
        self.assertTrue(lock.is_dir())
        self.assertGreater(lock.stat().st_mtime, 946684800)
        a_go.touch()
        overlapped = f.await_marker(a_copy, first, timeout=5)
        # If A bypassed B's lock, let A publish before B executes its mv.
        # With correct exclusion, release B so A can finish normally instead.
        first_result = f.finish(first) if overlapped else None
        b_go.touch()
        second_result = f.finish(second)
        if first_result is None:
            first_result = f.finish(first)
        published = f.snapshot_path(first_result)
        self.assertEqual(f.snapshot_path(second_result), published)
        self.assertEqual(
            f.file_tree(published), expected,
            "a stale age check removed B's fresh lock; mv nested .stage.* inside "
            "the published tree, which the engine recursively loads as rules",
        )
        self.assertFalse(overlapped, "two publishers held the critical section at once")

    def test_prune_cannot_delete_parallel_rollbacks_selected_snapshot(self):
        # B has selected an old snapshot but has not updated .env/Compose yet.
        # A's cleanup acquires .lock, reads the OLD .env and mount, then pauses
        # before deleting anything. B's unlocked .env task and Compose switch
        # run now. A must not remove the snapshot B just selected/mounted.
        f = self.fixture
        snapshots = []
        for index in range(5):
            (f.rules / "a.yml").write_text(f"id: release-{index}\n", encoding="utf-8")
            snapshot = f.snapshot_path(f.run_task())
            os.utime(snapshot, (1700000000 + index, 1700000000 + index))
            snapshots.append(snapshot)
        rollback, current = snapshots[0], snapshots[-1]
        (f.rules / "a.yml").write_text("id: release-0\n", encoding="utf-8")
        self.assertEqual(f.snapshot_path(f.run_task()), rollback)
        self.write_env(current)
        tools, mounted, calls = self.docker_fixture(current)
        ready, release = f.root / "prune-ready", f.root / "prune-go"
        f.gated_command(tools, "rm", ready, release)
        pruning = f.start_task(
            role.PRUNE, tools=tools,
            argus_rules_snapshot={"stdout": f"created {current}"},
        )
        self.assertTrue(f.await_marker(ready, pruning), "pruning never reached deletion")
        self.assertEqual(calls.read_text(encoding="utf-8"), "ps\ninspect\n")
        self.assertTrue((f.releases / ".lock").is_dir())
        self.write_env(rollback)
        mounted.write_text(str(rollback), encoding="utf-8")
        release.touch()
        result = f.finish(pruning)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (rollback / "a.yml").is_file(),
            "pruning deleted the concurrently selected snapshot: .env and engine "
            "can change while the cleanup's lock is held",
        )

    def test_prune_preserves_all_snapshots_when_engine_inspection_fails(self):
        # The registered snapshot, latest .env, and running engine can differ
        # during overlapping deployments. A failed observation is not evidence
        # that the oldest snapshot is unmounted. Stop/skip pruning on errors.
        f = self.fixture
        for failure in ("ps", "inspect"):
            with self.subTest(failure=failure):
                snapshots = self.seed_releases()
                mounted, selected, current = snapshots[0], snapshots[-2], snapshots[-1]
                self.write_env(selected)
                tools, _, calls = self.docker_fixture(mounted, fail_at=failure)
                result = f.run_task(
                    role.PRUNE, tools=tools,
                    argus_rules_snapshot={"stdout": f"created {current}"},
                )
                self.assertIn(failure, calls.read_text(encoding="utf-8").splitlines())
                # Both a failing task and a successful conservative no-op are
                # acceptable. In neither case may it delete an unknown mount.
                self.assertEqual(
                    {path for path in snapshots if (path / "a.yml").is_file()},
                    set(snapshots),
                    f"Docker {failure} failed, but cleanup still removed snapshots: "
                    + result.stdout + result.stderr,
                )

    def test_successful_inspection_preserves_env_mount_and_current(self):
        # Control: different .env and mount are legitimate during a rollout.
        f = self.fixture
        snapshots = self.seed_releases()
        mounted, selected, current = snapshots[0], snapshots[-2], snapshots[-1]
        self.write_env(selected)
        tools, _, calls = self.docker_fixture(mounted)
        result = f.run_task(
            role.PRUNE, tools=tools,
            argus_rules_snapshot={"stdout": f"created {current}"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.read_text(encoding="utf-8"), "ps\ninspect\n")
        self.assertEqual(
            set(f.releases.iterdir()),
            {mounted, selected, current, snapshots[2], snapshots[3]},
        )

    def test_rejects_symlink_added_after_checkout_scan_before_copy(self):
        # Another checkout/rsync can introduce a link after `find rules -type l`
        # but before cp. Only validating the prepared copy closes this window.
        f = self.fixture
        outside = f.root / "outside.yml"
        outside.write_text("id: mutable-external-rule\n", encoding="utf-8")
        link = f.rules / "late.yml"
        real_cp = shutil.which("cp", path=os.defpath)
        self.assertIsNotNone(real_cp)
        tools = f.wrapper(f.root / "link-inserting-copy", "cp", f"""
            import os
            from pathlib import Path
            import sys

            Path({str(link)!r}).symlink_to({str(outside)!r})
            os.execv({real_cp!r}, [{real_cp!r}, *sys.argv[1:]])
        """)
        result = f.run_task(tools=tools)
        self.assertTrue(link.is_symlink(), "the concurrent checkout mutation did not run")
        self.assertNotEqual(
            result.returncode, 0,
            "a symlink introduced after the checkout scan was published unhashed: "
            + result.stdout,
        )
        self.assertFalse(f.published_snapshots(), "rejected copies must not enter the cache")

    def assert_compose_mount_matches_snapshot(self, directory_name):
        f = self.fixture
        docker = shutil.which("docker")
        if docker is None:
            self.skipTest("Docker Compose CLI is required; no daemon is needed")
        config_dir = f.root / "docker-config"
        config_dir.mkdir()
        environment = {
            **f.environment,
            "DOCKER_CONFIG": str(config_dir),
            "DOCKER_HOST": "unix://" + str(f.root / "no-docker-daemon.sock"),
        }
        version = subprocess.run(
            [docker, "compose", "version"], env=environment, cwd=f.root,
            capture_output=True, text=True, timeout=15,
        )
        if version.returncode != 0:
            self.skipTest("Docker Compose CLI plugin is unavailable with an isolated config")
        f.releases = f.root / directory_name
        snapshot = f.snapshot_path(f.run_task())
        self.write_env(snapshot)
        compose = yaml.safe_load((role.ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        rules_mount, = [
            mount for mount in compose["services"]["engine"]["volumes"]
            if isinstance(mount, str) and "ARGUS_RULES_HOST_DIR" in mount
        ]
        # Keep the real interpolation/mount expression, but no application
        # dependencies, secrets, images, or sockets from the real deployment.
        model = {"services": {"engine": {
            "image": "argus-review.invalid/engine:fixture",
            "volumes": [rules_mount],
        }}}
        compose_file = f.checkout / "compose-fixture.json"
        compose_file.write_text(json.dumps(model), encoding="utf-8")
        result = subprocess.run(
            [docker, "compose", "--project-name", "argus-pr102-fixture",
             "--env-file", str(f.checkout / ".env"),
             "-f", str(compose_file), "config", "--format", "json"],
            cwd=f.checkout, env=environment, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        volumes = json.loads(result.stdout)["services"]["engine"]["volumes"]
        mount, = [volume for volume in volumes if volume["target"] == "/rules"]
        self.assertEqual(mount["type"], "bind")
        self.assertTrue(mount["read_only"])
        self.assertEqual(
            Path(mount["source"]), snapshot,
            "Compose must mount the directory created by the role, without dotenv "
            "quote termination or escape-sequence conversion",
        )

    def test_compose_preserves_space_in_snapshot_path(self):
        self.assert_compose_mount_matches_snapshot("rule snapshots")

    def test_compose_preserves_literal_quote_in_snapshot_path(self):
        self.assert_compose_mount_matches_snapshot('rules"archive')

    def test_compose_preserves_literal_backslash_in_snapshot_path(self):
        self.assert_compose_mount_matches_snapshot(r"rules\new")


if __name__ == "__main__":
    unittest.main()
