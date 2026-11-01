"""Offline safety/contract tests. These do NOT replace a Debian systemd install."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

import install as app

TEST_ROOT = Path(__file__).resolve().parent / ".test-tmp"


@contextlib.contextmanager
def fixture_directory():
    TEST_ROOT.mkdir(exist_ok=True)
    temporary = tempfile.TemporaryDirectory(prefix="fixture-", dir=TEST_ROOT)
    resolved = Path(temporary.name).resolve()
    if resolved.parent != TEST_ROOT.resolve():
        raise RuntimeError("Unexpected test cleanup path")
    try:
        yield str(resolved)
    finally:
        temporary.cleanup()


FAKE = {"uuid": "9c8900d8-6e81-4378-bf8a-9579b69d3592", "private": "A" * 43,
        "public": "B" * 43, "short_id": "1234567890abcdef"}
PROXY = {"address": "198.51.100.20", "port": 3128, "user": "fixture", "pass": "fixture-only"}


class InputTests(unittest.TestCase):
    def test_rejects_private_and_command_like_addresses(self):
        for address in ("127.0.0.1", "10.0.0.1", "192.168.2.1", "::1", "8.8.8.8;id",
                        "8.8.8.8\nls", "example.com", "224.0.0.1", "169.254.169.254"):
            with self.subTest(address=address), self.assertRaises(app.Stop):
                app.ipv4(address)
        self.assertEqual(app.ipv4(" 8.8.8.8 "), "8.8.8.8")

    def test_port_bounds(self):
        for value in ("0", "65536", "443;echo", "-1", "port"):
            with self.subTest(value=value), self.assertRaises(app.Stop):
                app.port_number(value)
        self.assertEqual(app.port_number("8443"), 8443)

    def test_occupied_port_is_not_reclaimed(self):
        with socket.socket() as listener:
            listener.bind(("0.0.0.0", 0))
            listener.listen()
            with self.assertRaises(app.Stop):
                app.check_port(listener.getsockname()[1])
            self.assertGreater(listener.fileno(), -1)

    def test_default_is_only_preflight(self):
        with patch.object(app, "preflight") as check, patch.object(app, "install") as install:
            self.assertEqual(app.main([]), 0)
            check.assert_called_once_with(443)
            install.assert_not_called()

    def test_install_requires_literal_confirmation(self):
        with patch.object(app, "check_runtime"), patch.object(app, "preflight"), \
             patch.object(app.sys.stdin, "isatty", return_value=True), \
             patch.object(app, "collect_options", return_value=("8.8.8.8", None, "8.8.8.8")), \
             patch("builtins.input", return_value="no"), patch.object(app, "download_release") as download, \
             patch.object(app.Path, "mkdir") as mkdir, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(app.Stop):
                app.install(443)
            download.assert_not_called()
            mkdir.assert_not_called()

    def test_refuses_windows_without_commands(self):
        with patch.object(app.sys, "platform", "win32"), patch.object(app, "command") as command:
            with self.assertRaises(app.Stop):
                app.preflight(443)
            command.assert_not_called()


class WizardTests(unittest.TestCase):
    def collect(self, answers, password="secret:with spaces & symbols"):
        output = io.StringIO()
        with patch("builtins.input", side_effect=answers), \
             patch.object(app.getpass, "getpass", return_value=password) as hidden, \
             contextlib.redirect_stdout(output):
            result = app.collect_options()
        self.assertNotIn(password, output.getvalue())
        return result, hidden

    def test_proxy_wizard_retries_bad_addresses_and_ports(self):
        (address, proxy, expected), hidden = self.collect([
            "not-an-ip", "8.8.8.8", "", "127.0.0.1", "1.1.1.1",
            "65536", "3128", "", "", "name:invalid", "proxy-login", "",
        ])
        self.assertEqual(address, "8.8.8.8")
        self.assertEqual(proxy, {"address": "1.1.1.1", "port": 3128,
                                "user": "proxy-login", "pass": "secret:with spaces & symbols"})
        self.assertEqual(expected, "1.1.1.1")
        hidden.assert_called_once()

    def test_ip_authorization_never_requests_or_stores_password(self):
        (_, proxy, expected), hidden = self.collect([
            "8.8.8.8", "2", "1.1.1.1", "3128", "2", "9.9.9.9",
        ])
        self.assertEqual(proxy, {"address": "1.1.1.1", "port": 3128})
        self.assertEqual(expected, "9.9.9.9")
        hidden.assert_not_called()
        config = app.build_template(8443, proxy)
        self.assertNotIn("freedom", [item["protocol"] for item in config["outbounds"]])

    def test_direct_mode_does_not_request_proxy(self):
        result, hidden = self.collect(["8.8.8.8", "invalid-mode", "1"])
        self.assertEqual(result, ("8.8.8.8", None, "8.8.8.8"))
        hidden.assert_not_called()

    def test_busy_and_internal_ports_offer_another_choice(self):
        with patch("builtins.input", side_effect=["2053", "62789", "443", "8443"]), \
             patch.object(app, "check_port", side_effect=[app.Stop("Занят"), None]) as check, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(app.ask("Порт", app.vpn_port, 443), 8443)
        self.assertEqual([call.args[0] for call in check.call_args_list], [443, 8443])

    def test_password_preserves_spaces_and_retries_control_characters(self):
        secret = "  exact ' & $ password  "
        output = io.StringIO()
        with patch.object(app.getpass, "getpass", side_effect=["", "bad\nvalue", secret]), \
             contextlib.redirect_stdout(output):
            self.assertEqual(app.ask_password(), secret)
        self.assertNotIn(secret, output.getvalue())
        self.assertNotIn("bad\nvalue", output.getvalue())

    def test_password_never_falls_back_to_visible_input(self):
        def unavailable(prompt):
            app.warnings.warn("Cannot hide password", app.getpass.GetPassWarning)
            self.fail("Warning must stop the insecure fallback")
        with patch.object(app.getpass, "getpass", side_effect=unavailable), \
             patch("builtins.input") as visible:
            with self.assertRaises(app.Stop):
                app.ask_password()
            visible.assert_not_called()

    def test_cli_prompts_for_install_port_or_uses_explicit_port(self):
        with patch.object(app, "install") as install:
            self.assertEqual(app.main(["--install"]), 0)
            install.assert_called_once_with(None)
            install.reset_mock()
            self.assertEqual(app.main(["--install", "--port", "8443"]), 0)
            install.assert_called_once_with(8443)

    def test_noninteractive_install_never_collects_credentials(self):
        with patch.object(app, "check_runtime"), \
             patch.object(app.sys.stdin, "isatty", return_value=False), \
             patch.object(app, "collect_options") as collect, patch("builtins.input") as prompt:
            with self.assertRaises(app.Stop):
                app.install()
            collect.assert_not_called()
            prompt.assert_not_called()

    def test_custom_port_is_preflighted_before_confirmation(self):
        with patch.object(app, "check_runtime"), patch.object(app, "preflight") as check, \
             patch.object(app.sys.stdin, "isatty", return_value=True), \
             patch.object(app, "check_port"), \
             patch.object(app, "collect_options", return_value=("8.8.8.8", None, "8.8.8.8")), \
             patch("builtins.input", side_effect=["8443", "no"]), \
             patch.object(app, "download_release") as download, \
             patch.object(app.Path, "mkdir") as mkdir, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(app.Stop):
                app.install()
            check.assert_called_once_with(8443)
            download.assert_not_called()
            mkdir.assert_not_called()


class QuickTests(unittest.TestCase):
    def test_quick_mode_only_asks_for_proxy_credentials(self):
        with patch.object(app, "server_address", return_value="8.8.8.8"), \
             patch("builtins.input", side_effect=["1.1.1.1", "3128", "proxy-login"]) as prompt, \
             patch.object(app.getpass, "getpass", return_value="  exact password  ") as hidden, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            address, proxy, expected = app.collect_quick_options()
        self.assertEqual(prompt.call_count, 3)
        hidden.assert_called_once()
        self.assertEqual(address, "8.8.8.8")
        self.assertEqual(expected, "1.1.1.1")
        self.assertEqual(proxy["pass"], "  exact password  ")
        self.assertNotIn(proxy["pass"], output.getvalue())

    def test_quick_flag_runs_quick_install(self):
        with patch.object(app, "install") as install:
            self.assertEqual(app.main(["--quick"]), 0)
            install.assert_called_once_with(None, quick=True)

    def test_auto_port_skips_busy_service_without_stopping_it(self):
        with patch.object(app, "check_port", side_effect=[app.Stop("Занят"), None]) as check:
            self.assertEqual(app.automatic_port(), 8443)
            self.assertEqual([call.args[0] for call in check.call_args_list], [443, 8443])

    def test_auto_port_asks_if_both_defaults_are_busy(self):
        with patch.object(app, "check_port", side_effect=[app.Stop("Занят"), app.Stop("Занят"), None]), \
             patch("builtins.input", return_value="9443"):
            self.assertEqual(app.automatic_port(), 9443)

    def test_ssh_detection_uses_server_side_not_client_ip(self):
        with patch.dict(app.os.environ, {"SSH_CONNECTION": "9.9.9.9 50000 8.8.8.8 22"}), \
             patch.object(app, "command") as command:
            self.assertEqual(app.server_address(), "8.8.8.8")
            command.assert_not_called()

    def test_nat_ssh_address_uses_direct_public_lookup(self):
        with patch.dict(app.os.environ, {"SSH_CONNECTION": "9.9.9.9 50000 10.0.0.1 22"}), \
             patch.object(app, "command", return_value="8.8.8.8\n") as command:
            self.assertEqual(app.server_address(), "8.8.8.8")
            self.assertIn("--noproxy", command.call_args.args[0])
            self.assertNotIn("HTTPS_PROXY", command.call_args.kwargs["env"])

    def test_failed_detection_asks_instead_of_guessing(self):
        with patch.dict(app.os.environ, {"SSH_CONNECTION": "invalid"}), \
             patch.object(app, "command", side_effect=app.Stop("Недоступно")), \
             patch("builtins.input", return_value="8.8.8.8"):
            self.assertEqual(app.server_address(), "8.8.8.8")


class RoutingTests(unittest.TestCase):
    def test_proxy_has_no_freedom_or_alternate_route(self):
        config = app.build_template(8443, PROXY)
        self.assertEqual(config["outbounds"][0]["protocol"], "blackhole")
        self.assertNotIn("freedom", [item["protocol"] for item in config["outbounds"]])
        self.assertNotIn("balancers", config["routing"])
        self.assertTrue(config["dns"]["disableFallback"])
        rules = config["routing"]["rules"]
        self.assertEqual(rules[1]["inboundTag"], ["dns-query"])
        self.assertEqual(rules[1]["outboundTag"], "egress")
        self.assertEqual(rules[2]["outboundTag"], "dns-out")
        self.assertEqual(rules[-2]["network"], "udp")
        self.assertEqual(rules[-2]["outboundTag"], "blocked")
        self.assertEqual(rules[-1]["inboundTag"], ["in-8443-tcp"])
        self.assertEqual(rules[-1]["outboundTag"], "egress")

    def test_direct_blocks_private_after_resolution(self):
        config = app.build_template(443, None)
        freedom = next(item for item in config["outbounds"] if item["protocol"] == "freedom")
        self.assertEqual(freedom["settings"]["finalRules"][0], {"action": "block", "ip": ["geoip:private"]})
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")

    def test_uri_contains_only_client_credentials(self):
        uri = app.profile_uri("198.51.100.10", 8443, FAKE)
        parsed = urlparse(uri)
        fields = parse_qs(parsed.query)
        self.assertEqual(parsed.hostname, "198.51.100.10")
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.fragment, "NL")
        self.assertEqual(fields["pbk"], [FAKE["public"]])
        self.assertEqual(fields["spx"], ["/"])
        self.assertNotIn(FAKE["private"], uri)
        self.assertNotIn(PROXY["pass"], uri)

    def test_inbound_and_client_share_identity(self):
        inbound = app.build_inbound(8443, FAKE)
        client = app.client_config(8443, 10800, FAKE)
        self.assertEqual(inbound["settings"]["clients"][0]["id"], FAKE["uuid"])
        self.assertEqual(client["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"], FAKE["uuid"])
        self.assertEqual(inbound["settings"]["fallbacks"], [])
        self.assertNotIn(FAKE["private"], json.dumps(client))

    def test_service_is_nonroot_with_limited_writes(self):
        unit = app.unit_text()
        self.assertIn("User=nl-vpn\n", unit)
        self.assertIn("ProtectSystem=strict\n", unit)
        self.assertIn("ProtectHome=yes\n", unit)
        self.assertIn(f"ReadWritePaths={app.DATA} {app.LOG}\n", unit)
        self.assertIn("NoNewPrivileges=yes\n", unit)
        self.assertNotIn("CAP_NET_ADMIN", unit)
        self.assertNotIn("CAP_DAC_OVERRIDE", unit)

    def test_environment_does_not_inherit_network_overrides(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://secret.invalid", "XUI_PORT": "80"}):
            env = app.clean_environment()
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertNotIn("XUI_PORT", env)
        self.assertEqual(env["XUI_DB_TYPE"], "sqlite")


class FileTests(unittest.TestCase):
    def make_archive(self, root, names, link=False):
        archive = root / "fixture.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name in names:
                item = tarfile.TarInfo(name)
                if link:
                    item.type, item.linkname = tarfile.SYMTYPE, "/etc/shadow"
                    tar.addfile(item)
                else:
                    item.size = 2
                    tar.addfile(item, io.BytesIO(b"ok"))
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def test_valid_archive(self):
        with fixture_directory() as temporary:
            root = Path(temporary)
            archive, digest = self.make_archive(root, ["x-ui/x-ui", "x-ui/bin/geoip.dat"])
            app.verified_extract(archive, root / "extracted", digest)
            self.assertEqual((root / "extracted/x-ui/x-ui").read_text(), "ok")

    def test_hash_mismatch_never_extracts(self):
        with fixture_directory() as temporary:
            root = Path(temporary)
            archive, _ = self.make_archive(root, ["x-ui/x-ui"])
            with self.assertRaises(app.Stop):
                app.verified_extract(archive, root / "extracted", "0" * 64)
            self.assertFalse((root / "extracted").exists())

    def test_unsafe_paths_and_duplicate_members_rejected_before_write(self):
        for name in ("../escape", "x-ui/../../escape", "/etc/escape", "x-ui\\escape", "other/file", "x-ui/safe"):
            with self.subTest(name=name), fixture_directory() as temporary:
                root = Path(temporary)
                archive, digest = self.make_archive(root, ["x-ui/safe", name])
                with self.assertRaises(app.Stop):
                    app.verified_extract(archive, root / "extracted", digest)
                self.assertFalse((root / "extracted").exists())

    def test_symlinks_rejected_before_write(self):
        with fixture_directory() as temporary:
            root = Path(temporary)
            archive, digest = self.make_archive(root, ["x-ui/file"], link=True)
            with self.assertRaises(app.Stop):
                app.verified_extract(archive, root / "extracted", digest)
            self.assertFalse((root / "extracted").exists())

    def test_secret_files_never_overwrite(self):
        with fixture_directory() as temporary:
            file = Path(temporary) / "access.txt"
            app.private_write(file, "original")
            with self.assertRaises(FileExistsError):
                app.private_write(file, "replacement")
            self.assertEqual(file.read_text(), "original")

    def test_database_parameterization_and_duplicate_setting_cleanup(self):
        with fixture_directory() as temporary:
            file = Path(temporary) / "new.db"
            with contextlib.closing(sqlite3.connect(file)) as database, database:
                database.execute('CREATE TABLE settings (id INTEGER PRIMARY KEY, "key" TEXT, value TEXT)')
                database.executemany('INSERT INTO settings ("key", value) VALUES (?, ?)',
                                     [("webListen", "0.0.0.0"), ("webListen", "::"), ("untouched", "keep")])
            secret = "single'quote; DROP TABLE settings; --"
            app.set_settings(file, {"webListen": "127.0.0.1", "secret": secret})
            with contextlib.closing(sqlite3.connect(file)) as database:
                rows = database.execute('SELECT "key", value FROM settings ORDER BY "key"').fetchall()
            self.assertEqual(rows, [("secret", secret), ("untouched", "keep"), ("webListen", "127.0.0.1")])


if __name__ == "__main__":
    unittest.main()
