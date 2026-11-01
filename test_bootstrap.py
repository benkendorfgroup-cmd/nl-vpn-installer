"""Offline shell checks: downloads, package manager and system checks are mocked."""
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import unittest

from test_install import fixture_directory

ROOT = Path(__file__).resolve().parent
BASH = shutil.which("bash") or (r"C:\Program Files\Git\bin\bash.exe" if os.name == "nt" else None)


def shell_path(path):
    path = Path(path).resolve().as_posix()
    if os.name == "nt":
        path = "/" + path[0].lower() + path[2:]
    return shlex.quote(path)


@unittest.skipUnless(BASH, "Bash not available")
class BootstrapTests(unittest.TestCase):
    def run_shell(self, body):
        return subprocess.run([BASH, "--noprofile", "--norc", "-c",
                               "source " + shell_path(ROOT / "bootstrap.sh") + "\n" + body],
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=15)

    def test_shell_syntax(self):
        result = subprocess.run([BASH, "-n", str(ROOT / "bootstrap.sh")],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_launch_command_syntax(self):
        command = (ROOT / "COMMAND.txt").read_text(encoding="utf-8").strip()
        parts = shlex.split(command)
        self.assertEqual(parts[:2], ["sh", "-c"])
        self.assertEqual(len(parts), 3)
        result = subprocess.run([BASH, "-n", "-c", parts[2]], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_pinned_hashes_match_files(self):
        bootstrap = (ROOT / "bootstrap.sh").read_bytes()
        match = re.search(rb"INSTALLER_SHA256='([a-f0-9]{64})'", bootstrap)
        self.assertIsNotNone(match)
        self.assertEqual(match[1].decode(), hashlib.sha256((ROOT / "install.py").read_bytes()).hexdigest())
        command = (ROOT / "COMMAND.txt").read_text(encoding="utf-8")
        self.assertIn(hashlib.sha256(bootstrap).hexdigest(), command)

    def test_guard_failure_does_not_prepare_packages(self):
        result = self.run_shell("check_system() { return 19; }; prepare_packages() { echo UNEXPECTED; }; main")
        self.assertEqual(result.returncode, 19, result.stderr.decode(errors="replace"))
        self.assertNotIn(b"UNEXPECTED", result.stdout)

    def test_existing_packages_do_not_call_apt(self):
        result = self.run_shell("dpkg-query() { printf 'install ok installed'; }; apt-get() { echo UNEXPECTED; return 20; }; prepare_packages")
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertNotIn(b"UNEXPECTED", result.stdout)

    def test_missing_packages_do_not_upgrade_or_remove(self):
        result = self.run_shell("dpkg-query() { return 1; }; apt-get() { printf '%s\\n' \"$*\"; }; prepare_packages")
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"--no-upgrade --no-remove python3 curl ca-certificates iproute2", result.stdout)

    def download_case(self, expected, failure=False):
        with fixture_directory() as temporary:
            folder = Path(temporary)
            fixture = folder / "fixture.txt"
            fixture.write_bytes(b"fixture installer\n")
            result = self.run_shell(
                "INSTALLER_SHA256=" + shlex.quote(expected) + "\n"
                "curl() { cat " + shell_path(fixture) + " > \"${@: -1}\"; return " + ("22" if failure else "0") + "; }\n"
                "fetch_installer " + shell_path(folder))
            return result, (folder / "install.py").exists()

    def test_only_verified_download_is_promoted(self):
        digest = hashlib.sha256(b"fixture installer\n").hexdigest()
        result, exists = self.download_case(digest)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertTrue(exists)

    def test_bad_hash_is_never_promoted(self):
        result, exists = self.download_case("0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(exists)

    def test_partial_download_is_never_promoted(self):
        digest = hashlib.sha256(b"fixture installer\n").hexdigest()
        result, exists = self.download_case(digest, failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(exists)


if __name__ == "__main__":
    unittest.main()
