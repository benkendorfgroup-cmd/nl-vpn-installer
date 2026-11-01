#!/usr/bin/env python3
"""Small, pinned 3x-ui/VLESS installer. No action without --install + confirmation.

Only Python's standard library is required. Run on Debian 13, never on Windows.
Credentials are generated or entered on the target; this file contains none.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import getpass
import hashlib
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import signal
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import warnings

VERSION = "v3.11.0"
RELEASES = {
    "x86_64": ("amd64", "0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916"),
    "aarch64": ("arm64", "f50b4c30fd919d018f2f4c3d8db53a4ca027503d581328727770afb116a79d90"),
}
APP = Path("/opt/nl-vpn")
DATA = Path("/var/lib/nl-vpn")
LOG = Path("/var/log/nl-vpn")
ACCESS = Path("/root/nl-vpn-access")
UNIT = Path("/etc/systemd/system/nl-vpn.service")
ACCOUNT = "nl-vpn"
PANEL_PORT, API_PORT = 2053, 62789
MAX_ARCHIVE = 150 * 1024 * 1024
MAX_EXTRACTED = 500 * 1024 * 1024
SNI = "www.microsoft.com"


class Stop(Exception):
    """A safe, user-facing error. Never put raw subprocess/API responses here."""


def ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value.strip())
    except ValueError:
        raise Stop("Нужен корректный публичный IPv4, например адрес из панели VPS.") from None
    if not address.is_global or address.is_multicast:
        raise Stop("Адрес должен быть публичным IPv4.")
    return str(address)


def port_number(value: str | int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise Stop("Порт должен быть числом от 1 до 65535.") from None
    if not 1 <= number <= 65535:
        raise Stop("Порт должен быть числом от 1 до 65535.")
    return number


def command(argv, *, env=None, timeout=30, log=False):
    try:
        result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Stop(f"Не удалось выполнить {Path(argv[0]).name} за отведённое время.") from None
    if log and LOG.is_dir():
        with (LOG / "setup.log").open("ab") as file:
            file.write(result.stdout + result.stderr)
    if result.returncode:
        raise Stop(f"Команда {Path(argv[0]).name} завершилась с ошибкой. Установка остановлена.")
    return result.stdout.decode("utf-8", "replace")


def clean_environment():
    # No ambient proxy credentials, Node settings, or inherited XUI_* overrides.
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
            "HOME": str(DATA), "XUI_DB_FOLDER": str(DATA / "db"),
            "XUI_DB_TYPE": "sqlite", "XUI_BIN_FOLDER": str(DATA / "bin"),
            "XUI_LOG_FOLDER": str(LOG), "XUI_ENABLE_FAIL2BAN": "false",
            "XRAY_LOCATION_ASSET": str(DATA / "bin")}


def service_command(argv, **kwargs):
    return command(["runuser", "-u", ACCOUNT, "--", *map(str, argv)],
                   env=clean_environment(), **kwargs)


def check_port(port: int):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("0.0.0.0", port))
    except OSError:
        raise Stop(f"TCP-порт {port} уже занят или недоступен. Существующую службу не трогаю.") from None


def check_runtime():
    if sys.platform != "linux":
        raise Stop("Этот установщик запускается только на сервере Debian 13 через SSH.")
    if os.geteuid() != 0:
        raise Stop("Запусти проверку с sudo: sudo python3 install.py --check")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "debian" or release.get("VERSION_ID") != "13":
        raise Stop("Эта версия установщика рассчитана на Debian 13. ОС автоматически не меняется.")
    if platform.machine() not in RELEASES:
        raise Stop("Поддерживаются только Debian amd64 и arm64.")
    if not Path("/run/systemd/system").is_dir():
        raise Stop("Нужен сервер с systemd; контейнер без systemd не подходит.")


def preflight(port: int):
    check_runtime()
    required = ("systemctl", "systemd-analyze", "useradd", "runuser", "curl", "ss")
    missing = [name for name in required if not shutil.which(name)]
    if missing:
        raise Stop("Не найдены команды: " + ", ".join(missing) + ". См. README.md.")
    import pwd
    import grp
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup(ACCOUNT)
        except KeyError:
            pass
        else:
            raise Stop("Учётная запись или группа nl-vpn уже существует. Повторная установка запрещена.")
    for path in (APP, DATA, LOG, ACCESS, UNIT, Path(str(UNIT) + ".d"),
                 Path("/etc/x-ui"), Path("/usr/local/x-ui"), Path("/opt/x-ui"),
                 Path("/etc/systemd/system/x-ui.service")):
        if os.path.lexists(path):
            raise Stop(f"Уже существует {path}. Ничего не перезаписываю.")
    for parent in (APP.parent, DATA.parent, LOG.parent, ACCESS.parent, UNIT.parent):
        if not parent.is_dir() or parent.resolve() != parent:
            raise Stop(f"Необычное расположение каталога {parent}; нужна ручная проверка.")
        if shutil.disk_usage(parent).free < 750 * 1024 * 1024:
            raise Stop(f"В разделе {parent} нужно хотя бы 750 МБ свободного места.")
    mem = re.search(r"^MemAvailable:\s+(\d+)", Path("/proc/meminfo").read_text(), re.M)
    if not mem or int(mem.group(1)) < 512 * 1024:
        raise Stop("Нужно хотя бы 512 МБ доступной оперативной памяти.")
    if port in (PANEL_PORT, API_PORT):
        raise Stop("Порт подключения совпал со служебным портом панели.")
    for value in (port, PANEL_PORT, API_PORT):
        check_port(value)
    print(f"Проверка пройдена: Debian 13, {platform.machine()}, нужные порты свободны.")
    print("Файлы других служб и их данные не читались. Файрвол и внешняя доступность ещё не проверены.")


def private_write(path: Path, value: str):
    with path.open("x", encoding="utf-8", newline="\n") as file:
        os.chmod(path, 0o600)
        file.write(value)


def json_write(path: Path, value):
    private_write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def verified_extract(archive: Path, destination: Path, digest: str):
    with archive.open("rb") as file:
        actual = hashlib.file_digest(file, "sha256").hexdigest()
    if not secrets.compare_digest(actual, digest):
        raise Stop("SHA-256 архива не совпал с закреплённой версией. Ничего не запускаю.")
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        total, seen = 0, set()
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "\\" in member.name or ":" in member.name
                    or not path.parts or path.parts[0] != "x-ui"
                    or not (member.isdir() or member.isfile()) or path in seen):
                raise Stop("Неожиданное содержимое архива. Распаковка отменена.")
            total += member.size
            seen.add(path)
        if total > MAX_EXTRACTED or len(members) > 1000:
            raise Stop("Архив превышает ожидаемый размер.")
        # Validate the entire member list before creating any extracted file.
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with tar.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                os.chmod(target, 0o600)


def download_release(architecture: str, destination: Path):
    url = f"https://github.com/MHSanaei/3x-ui/releases/download/{VERSION}/x-ui-linux-{architecture}.tar.gz"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=30) as response, destination.open("xb") as output:
            if not response.url.startswith("https://"):
                raise Stop("Загрузка должна идти по HTTPS.")
            size, started = 0, time.monotonic()
            while chunk := response.read(128 * 1024):
                size += len(chunk)
                if size > MAX_ARCHIVE or time.monotonic() - started > 300:
                    raise Stop("Загрузка слишком большая или слишком долгая; остановлена.")
                output.write(chunk)
    except (OSError, TimeoutError):
        raise Stop("Не удалось скачать официальный архив с GitHub. Повторная загрузка автоматически не запускается.") from None


def build_template(port: int, proxy: dict | None):
    tag = f"in-{port}-tcp"
    route = lambda inbound, outbound, **fields: {
        "type": "field", "inboundTag": [inbound], "outboundTag": outbound, **fields}
    egress = ({"tag": "egress", "protocol": "http", "settings": proxy} if proxy else
              {"tag": "egress", "protocol": "freedom", "settings": {
                  "finalRules": [{"action": "block", "ip": ["geoip:private"]}, {"action": "allow"}]}})
    rules = [route("api", "api"), route("dns-query", "egress"),
             route(tag, "dns-out", network="tcp,udp", port="53"),
             {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"}]
    if proxy:
        rules.append(route(tag, "blocked", network="udp"))
    rules.append(route(tag, "egress"))
    return {
        "log": {"access": "none", "error": "", "loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService", "RoutingService"]},
        "inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": API_PORT,
                      "protocol": "tunnel", "settings": {"rewriteAddress": "127.0.0.1"}}],
        # Unknown/new inbounds are blocked until explicitly assigned a route.
        "outbounds": [{"tag": "blocked", "protocol": "blackhole", "settings": {}},
                      egress, {"tag": "dns-out", "protocol": "dns", "settings": {}}],
        "dns": {"servers": ["https://1.1.1.1/dns-query"], "tag": "dns-query",
                "queryStrategy": "UseIPv4", "disableFallback": True},
        "routing": {"domainStrategy": "AsIs", "rules": rules},
        "policy": {"levels": {"0": {"statsUserDownlink": True, "statsUserUplink": True}},
                   "system": {"statsInboundDownlink": True, "statsInboundUplink": True}},
        "stats": {},
    }


def build_inbound(port: int, credentials: dict):
    return {
        "remark": "NL", "enable": True, "listen": "0.0.0.0", "port": port,
        "protocol": "vless", "expiryTime": 0, "total": 0,
        "settings": {"clients": [{"id": credentials["uuid"], "flow": "xtls-rprx-vision",
            "email": "device-1", "limitIp": 0, "totalGB": 0, "expiryTime": 0,
            "enable": True, "tgId": "", "subId": secrets.token_hex(8), "reset": 0}],
            "decryption": "none", "fallbacks": []},
        "streamSettings": {"network": "tcp", "security": "reality",
            "realitySettings": {"show": False, "dest": SNI + ":443", "xver": 0,
                "serverNames": [SNI], "privateKey": credentials["private"],
                "shortIds": [credentials["short_id"]], "maxTimeDiff": 60000,
                "settings": {"publicKey": credentials["public"], "fingerprint": "chrome",
                             "serverName": SNI, "spiderX": "/"}},
            "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                     "metadataOnly": False, "routeOnly": True},
    }


def profile_uri(address: str, port: int, credentials: dict):
    parameters = {"encryption": "none", "security": "reality", "sni": SNI,
                  "fp": "chrome", "pbk": credentials["public"], "sid": credentials["short_id"],
                  "type": "tcp", "flow": "xtls-rprx-vision", "spx": "/"}
    return f"vless://{credentials['uuid']}@{address}:{port}?{urllib.parse.urlencode(parameters)}#NL"


def set_settings(path: Path, values: dict):
    # This function is only called on the database created by this installation.
    with contextlib.closing(sqlite3.connect(path)) as database, database:
        for key, value in values.items():
            database.execute('DELETE FROM settings WHERE "key" = ?', (key,))
            database.execute('INSERT INTO settings ("key", value) VALUES (?, ?)', (key, str(value)))


def unit_text():
    return f"""[Unit]
Description=NL private 3x-ui panel and Xray
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=3

[Service]
Type=simple
User={ACCOUNT}
Group={ACCOUNT}
WorkingDirectory={APP}
ExecStart={APP}/x-ui
Environment=HOME={DATA}
Environment=XUI_DB_FOLDER={DATA}/db
Environment=XUI_DB_TYPE=sqlite
Environment=XUI_BIN_FOLDER={DATA}/bin
Environment=XUI_LOG_FOLDER={LOG}
Environment=XUI_ENABLE_FAIL2BAN=false
Environment=XRAY_LOCATION_ASSET={DATA}/bin
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
KillMode=control-group
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths={DATA} {LOG}
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
MemoryMax=768M
TasksMax=128
StandardOutput=append:{LOG}/panel.log
StandardError=append:{LOG}/panel.log

[Install]
WantedBy=multi-user.target
"""


class Panel:
    def __init__(self, basepath):
        self.origin = f"http://127.0.0.1:{PANEL_PORT}"
        self.base = self.origin + basepath.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                         urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = ""

    def request(self, path, data=None, form=False):
        headers = {"Origin": self.origin, "Referer": self.base + "/",
                   "X-Requested-With": "XMLHttpRequest"}
        body = None
        if data is not None:
            body = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
            headers["X-CSRF-Token"] = self.csrf
        try:
            with self.opener.open(urllib.request.Request(self.base + path, body, headers), timeout=10) as response:
                result = json.load(response)
        except (OSError, ValueError):
            raise Stop("Локальная панель не ответила корректно. Содержимое ответа скрыто.") from None
        if not isinstance(result, dict) or not result.get("success"):
            raise Stop("Панель отклонила операцию. Проверь приватный журнал установки.")
        return result.get("obj")

    def login(self, username, password):
        self.csrf = self.request("/csrf-token")
        self.request("/login", {"username": username, "password": password}, form=True)
        self.csrf = self.request("/csrf-token")


def wait_port(port, timeout=20):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.3)
    raise Stop(f"Локальный порт {port} не открылся вовремя.")


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def running_core(xray: Path, config: dict, folder: Path, name: str, port: int):
    file = folder / (name + ".json")
    json_write(file, config)
    command([str(xray), "run", "-test", "-c", str(file)], env=clean_environment(), log=True)
    process = None
    try:
        with (folder / (name + ".log")).open("xb") as log:
            process = subprocess.Popen([str(xray), "run", "-c", str(file)],
                env=clean_environment(), stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            wait_port(port, 10)
            if process.poll() is not None:
                raise Stop("Проверочный процесс Xray завершился раньше времени.")
            yield
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)


def client_config(port: int, socks_port: int, credentials: dict):
    return {"log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{
            "address": "127.0.0.1", "port": port, "users": [{"id": credentials["uuid"],
            "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "fingerprint": "chrome", "serverName": SNI, "publicKey": credentials["public"],
                "shortId": credentials["short_id"], "spiderX": "/"}}}]}


def curl_ip(socks_port: int):
    # -q ignores a possible root .curlrc; never fall back to an environment proxy.
    return command(["curl", "-q", "--noproxy", "", "--proxy", f"socks5h://127.0.0.1:{socks_port}",
        "--silent", "--show-error", "--fail", "--connect-timeout", "8", "--max-time", "20",
        "https://api.ipify.org"], env=clean_environment(), timeout=25).strip()


def recv_exact(sock, count):
    chunks = bytearray()
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise Stop("Соединение DNS завершилось до ответа.")
        chunks.extend(chunk)
    return bytes(chunks)


def dns_check(socks_port: int):
    # SOCKS CONNECT -> VPN -> server DNS outbound -> DoH through the chosen egress.
    with socket.create_connection(("127.0.0.1", socks_port), timeout=10) as sock:
        sock.settimeout(15)
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise Stop("Не удалось открыть SOCKS для проверки DNS.")
        sock.sendall(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x35")
        reply = recv_exact(sock, 4)
        if reply[:2] != b"\x05\x00":
            raise Stop("Проверка DNS: SOCKS отклонил соединение.")
        length = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            length = recv_exact(sock, 1)[0]
        if length is None:
            raise Stop("Некорректный ответ SOCKS.")
        recv_exact(sock, length + 2)
        query_id = secrets.randbelow(65536)
        query = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
        query += b"\x07example\x03com\x00\x00\x01\x00\x01"
        sock.sendall(struct.pack("!H", len(query)) + query)
        size = struct.unpack("!H", recv_exact(sock, 2))[0]
        answer = recv_exact(sock, size)
        if len(answer) < 12:
            raise Stop("DNS вернул неполный ответ.")
        identifier, flags, _, answers, _, _ = struct.unpack("!6H", answer[:12])
        if identifier != query_id or not flags & 0x8000 or flags & 0xF or not answers:
            raise Stop("DNS через подключение не прошёл проверку.")


def verify_egress(xray, port, credentials, expected_ip, template):
    with tempfile.TemporaryDirectory(prefix="nl-vpn-check-", dir=ACCESS) as temporary:
        folder = Path(temporary)
        socks_port = unused_port()
        with running_core(xray, client_config(port, socks_port, credentials), folder, "client", socks_port):
            actual = ipv4(curl_ip(socks_port))
            if actual != expected_ip:
                raise Stop("Выходной IP не совпал с ожидаемым. Служба будет остановлена; прямой обход не включается.")
            dns_check(socks_port)
        # Exercise the identical routing/outbound policy in a separate process.
        # The installed service is never reconfigured to simulate a failure.
        if any(item["protocol"] == "http" for item in template["outbounds"]):
            failed = copy.deepcopy(template)
            failed.pop("api", None)
            failed.pop("stats", None)
            failed.pop("policy", None)
            probe_port = unused_port()
            failed["inbounds"] = [{"tag": f"in-{port}-tcp", "listen": "127.0.0.1",
                "port": probe_port, "protocol": "socks", "settings": {"auth": "noauth"}}]
            # Keep a port reserved but not listening: TCP connection is refused.
            with socket.socket() as closed:
                closed.bind(("127.0.0.1", 0))
                egress = next(item for item in failed["outbounds"] if item["tag"] == "egress")
                egress["settings"] = {"address": "127.0.0.1", "port": closed.getsockname()[1]}
                with running_core(xray, failed, folder, "failed-proxy", probe_port):
                    try:
                        curl_ip(probe_port)
                    except Stop:
                        pass
                    else:
                        raise Stop("Проверка отказа прокси не пройдена: запрос неожиданно выполнился.")
    return actual


def ask(prompt, validate, default=None):
    """Retry input errors without restarting the wizard or writing any files."""
    suffix = f" [{default}]" if default is not None else ""
    while True:
        value = input(prompt + suffix + ": ").strip()
        if not value and default is not None:
            value = str(default)
        try:
            return validate(value)
        except Stop as error:
            print(str(error))


def choice(value):
    if value not in ("1", "2"):
        raise Stop("Введи 1 или 2.")
    return value


def vpn_port(value):
    port = port_number(value)
    if port in (PANEL_PORT, API_PORT):
        raise Stop("Этот порт нужен панели. Выбери другой, например 443 или 8443.")
    check_port(port)
    return port


def proxy_username(value):
    if not value or ":" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Stop("Логин не должен быть пустым, содержать двоеточие или служебные символы.")
    return value


def ask_password():
    while True:
        try:
            with warnings.catch_warnings():
                # getpass otherwise falls back to visible input on a broken terminal.
                warnings.simplefilter("error", getpass.GetPassWarning)
                password = getpass.getpass("Пароль прокси (ввод скрыт): ")
        except getpass.GetPassWarning:
            raise Stop("Терминал не позволяет скрыть пароль. Открой обычное SSH-соединение и повтори запуск.") from None
        if password and not any(ord(c) < 32 or ord(c) == 127 for c in password):
            return password
        print("Нужен непустой пароль без служебных символов. Попробуй ещё раз.")


def collect_options():
    print("\nАдрес VPS — из панели сервера. Адрес и HTTP-порт прокси — из кабинета Proxy-Seller.")
    print("Это разные адреса. SSH-пароль сюда вводить не нужно.")
    address = ask("Публичный IPv4 этого VPS", ipv4)
    mode = ask("Выход: 1 — через IP VPS; 2 — через купленный HTTP-прокси", choice, "2")
    proxy, expected = None, address
    if mode == "2":
        host = ask("Адрес подключения к прокси (IPv4)", ipv4)
        port = ask("HTTP-порт прокси из кабинета продавца (не SOCKS и не SSH)", port_number)
        auth = ask("Вход в прокси: 1 — логин и пароль; 2 — IP VPS уже разрешён у продавца", choice, "1")
        proxy = {"address": host, "port": port}
        if auth == "1":
            proxy["user"] = ask("Логин прокси (не SSH-логин)", proxy_username)
            proxy["pass"] = ask_password()
        else:
            print(f"В кабинете продавца должен быть разрешён IP этого VPS: {address}.")
            print("Установщик не меняет кабинет продавца. При отказе доступа прямого обхода не будет.")
        print("Внешний IP — адрес, который должны видеть сайты. Для отдельного статического прокси обычно он совпадает с адресом выше.")
        expected = ask("Ожидаемый внешний IPv4 прокси", ipv4, host)
    return address, proxy, expected


def automatic_port():
    for candidate in (443, 8443):
        try:
            return vpn_port(candidate)
        except Stop:
            continue
    return ask("Порты 443 и 8443 заняты. Введи свободный порт нового VPN", vpn_port)


def server_address():
    # Use the server-side address of the current SSH connection when public.
    fields = os.environ.get("SSH_CONNECTION", "").split()
    if len(fields) == 4:
        try:
            return ipv4(fields[2])
        except Stop:
            pass
    try:
        return ipv4(command(["curl", "-q", "--noproxy", "*", "--ipv4",
            "--silent", "--show-error", "--fail", "--connect-timeout", "3", "--max-time", "8",
            "https://api.ipify.org"], env=clean_environment(), timeout=10))
    except Stop:
        return ask("Не удалось определить адрес автоматически. Публичный IPv4 этого VPS", ipv4)


def collect_quick_options():
    address = server_address()
    print(f"\nАдрес сервера: {address}.")
    print("Введи четыре значения из кабинета Proxy-Seller. SSH-пароль сюда не нужен.")
    host = ask("IP купленного статического прокси", ipv4)
    port = ask("HTTP-порт прокси (не SOCKS)", port_number)
    username = ask("Логин прокси", proxy_username)
    password = ask_password()
    return address, {"address": host, "port": port, "user": username, "pass": password}, host


def install(port: int | None = None, *, quick=False):
    check_runtime()
    if not sys.stdin.isatty():
        raise Stop("Установка требует интерактивного SSH-терминала.")
    print("\nМастер установки NL. До подтверждения настройки VPN не меняются.")
    if port is None:
        port = automatic_port() if quick else ask(
            "Порт нового VPN: обычно 443; если занят сайтом — выбери 8443", vpn_port, 443)
    preflight(port)
    address, proxy, expected = collect_quick_options() if quick else collect_options()
    print(f"\nБудут созданы отдельная служба nl-vpn и подключение TCP/{port} на {address}.")
    print("Панель: только 127.0.0.1:2053. SSH, системный DNS и правила файрвола не меняются.")
    print("Чужие каталоги не читаются. Повторная установка и перезапись существующих файлов запрещены.")
    print(f"Ожидаемый выход: {expected}. Режим: {'HTTP-прокси' if proxy else 'IP VPS'}.")
    if input("Для установки введи INSTALL: ").strip() != "INSTALL":
        raise Stop("Отменено. Служба VPN не создавалась.")
    # Repeat immediately before mutation to catch state changes during the prompts.
    preflight(port)
    architecture, digest = RELEASES[platform.machine()]
    created_unit = False
    os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="nl-vpn-release-", dir="/root") as temporary:
            temporary = Path(temporary)
            archive = temporary / "release.tar.gz"
            print("Скачиваю закреплённую версию с GitHub и проверяю SHA-256…")
            download_release(architecture, archive)
            verified_extract(archive, temporary, digest)
            source = temporary / "x-ui"
            xray_name = f"xray-linux-{architecture}"
            for file in (source / "x-ui", source / "bin" / xray_name, source / "bin" / "geoip.dat"):
                if not file.is_file():
                    raise Stop("В официальном архиве нет необходимого файла.")
            APP.mkdir(mode=0o755)
            os.chmod(APP, 0o755)  # umask 0077 must not hide the executable from nl-vpn.
            for directory in (DATA, LOG, ACCESS, DATA / "bin", DATA / "db"):
                directory.mkdir(mode=0o700)
            shutil.copyfile(source / "x-ui", APP / "x-ui")
            os.chmod(APP / "x-ui", 0o755)
            for file in (source / "bin").iterdir():
                if file.name == xray_name or file.suffix == ".dat":
                    shutil.copyfile(file, DATA / "bin" / file.name)
                    os.chmod(DATA / "bin" / file.name, 0o700 if file.name == xray_name else 0o600)
        command(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", str(DATA),
                 "--shell", "/usr/sbin/nologin", ACCOUNT])
        import pwd
        account = pwd.getpwnam(ACCOUNT)
        for directory in (DATA, LOG, DATA / "bin", DATA / "db"):
            os.chown(directory, account.pw_uid, account.pw_gid)
        for file in (DATA / "bin").iterdir():
            os.chown(file, account.pw_uid, account.pw_gid)
        xray = DATA / "bin" / xray_name
        print("Создаю приватную панель и новые ключи подключения…")
        service_command([APP / "x-ui", "setting", "-listenIP", "127.0.0.1", "-port", str(PANEL_PORT)], log=True)
        basepath = "/" + secrets.token_urlsafe(24) + "/"
        template = build_template(port, proxy)
        settings = {"webListen": "127.0.0.1", "webPort": PANEL_PORT, "webBasePath": basepath,
                    "secret": secrets.token_urlsafe(32), "subEnable": "false", "subJsonEnable": "false",
                    "subListen": "127.0.0.1", "xrayTemplateConfig": json.dumps(template)}
        set_settings(DATA / "db" / "x-ui.db", settings)
        key_output = service_command([xray, "x25519"])
        pairs = {key.lower().replace(" ", ""): value.strip() for key, value in
                 re.findall(r"^([^:\r\n]+):\s*([^\r\n]+)", key_output, re.M)}
        credentials = {"uuid": str(uuid.uuid4()), "private": pairs.get("privatekey", ""),
                       "public": pairs.get("publickey", pairs.get("password", "")),
                       "short_id": secrets.token_hex(8)}
        if not all(re.fullmatch(r"[A-Za-z0-9_-]{43}", credentials[key]) for key in ("private", "public")):
            raise Stop("Не удалось распознать ключи REALITY; установка остановлена.")
        # Validate the routing template before starting the panel.
        candidate = ACCESS / "template-check.json"
        json_write(candidate, template)
        command([str(xray), "run", "-test", "-c", str(candidate)], env=clean_environment(), log=True)
        candidate.unlink()
        private_write(UNIT, unit_text())
        created_unit = True
        os.chmod(UNIT, 0o644)
        command(["systemd-analyze", "verify", str(UNIT)], log=True)
        command(["systemctl", "daemon-reload"])
        command(["systemctl", "start", "nl-vpn.service"], timeout=40, log=True)
        wait_port(PANEL_PORT)
        log = (LOG / "panel.log").read_text(errors="replace")
        match = re.search(r"Username: (\S+)\s+Password: (\S+)\s+\(shown once", log)
        if not match:
            raise Stop("Панель запущена, но её сгенерированный пароль не найден. Служба будет остановлена.")
        username, password = match.groups()
        access = (f"3x-ui {VERSION}\nПанель через SSH: http://127.0.0.1:{PANEL_PORT}{basepath}\n"
                  f"Логин: {username}\nПароль: {password}\n\n"
                  f"В PowerShell на своём компьютере (замени SSH_USER):\n"
                  f"ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:{PANEL_PORT}:127.0.0.1:{PANEL_PORT} SSH_USER@{address}\n"
                  "Оставь это окно открытым и открой локальный адрес панели в браузере.\n"
                  "Не открывай порт 2053 в файрволе и не меняй адрес панели на 0.0.0.0.\n")
        private_write(ACCESS / "panel.txt", access)
        panel = Panel(basepath)
        panel.login(username, password)
        if panel.request("/panel/api/inbounds/list"):
            raise Stop("В новой панели неожиданно уже есть подключения; останавливаюсь.")
        inbound = build_inbound(port, credentials)
        panel.request("/panel/api/inbounds/add", inbound)
        listed = panel.request("/panel/api/inbounds/list")
        if len(listed) != 1 or listed[0].get("tag") != f"in-{port}-tcp":
            raise Stop("Панель создала неожиданное правило подключения. Служба будет остановлена.")
        wait_port(port)
        print("Проверяю VLESS, выходной IP, DNS и остановку трафика при отказе прокси…")
        actual = verify_egress(xray, port, credentials, expected, template)
        # ss output stays local; only check our panel/API bind addresses.
        listeners = command(["ss", "-H", "-ltn"])
        for internal in (PANEL_PORT, API_PORT):
            rows = [line for line in listeners.splitlines() if line.split()[3].endswith(f":{internal}")]
            if not rows or any(line.split()[3] != f"127.0.0.1:{internal}" for line in rows):
                raise Stop("Служебный порт слушает не только localhost. Служба будет остановлена.")
        command(["systemctl", "is-active", "--quiet", "nl-vpn.service"])
        command(["systemctl", "enable", "nl-vpn.service"], log=True)
        uri = profile_uri(address, port, credentials)
        private_write(ACCESS / "NL.txt", uri + "\n")
        report = {"installed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "panel_version": VERSION, "release_sha256": digest, "exit_ip": actual,
                  "mode": "http-proxy" if proxy else "direct", "tcp_port": port,
                  "checks": {"server_vless_roundtrip": True, "dns_via_vpn": True,
                             "proxy_failure_in_isolated_copy": bool(proxy), "panel_loopback_only": True},
                  "external_client_test": "pending", "client_kill_switch_test": "pending"}
        json_write(ACCESS / "result.json", report)
        print(f"\nСерверная проверка пройдена. Выходной IP: {actual}.")
        print("\nГотовая ссылка подключения — скопируй всю следующую строку в VPN-клиент:")
        print(uri)
        print("Ссылка даёт доступ к VPN. Не публикуй её.")
        print(f"Получить её снова: sudo cat {ACCESS}/NL.txt")
        print(f"Доступ к панели: sudo cat {ACCESS}/panel.txt")
        print(f"Осталось разрешить только TCP/{port} в используемом файрволе и проверить с другого устройства.")
    except BaseException:
        if created_unit:
            # Do not disable/stop any service that wasn't created by this invocation.
            subprocess.run(["systemctl", "disable", "--now", "nl-vpn.service"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=40)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="NL: 3x-ui на Debian 13. По умолчанию только проверка.")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="Проверить совместимость без установки (по умолчанию)")
    action.add_argument("--install", action="store_true", help="Проверка и интерактивная установка")
    action.add_argument("--quick", action="store_true", help="Установка через статический HTTP-прокси: автоматический адрес VPS и порт VPN")
    parser.add_argument("--port", help="TCP-порт VLESS: при установке спрашивается; для --check по умолчанию 443")
    args = parser.parse_args(argv)
    try:
        if (args.install or args.quick) and sys.platform == "linux":
            def interrupted(signum, frame):
                raise KeyboardInterrupt
            signal.signal(signal.SIGTERM, interrupted)
            signal.signal(signal.SIGHUP, interrupted)
        port = port_number(args.port) if args.port is not None else None
        if args.quick:
            install(port, quick=True)
        elif args.install:
            install(port)
        else:
            preflight(port if port is not None else 443)
        return 0
    except (Stop, KeyboardInterrupt, EOFError) as error:
        print("\nОстановлено: " + (str(error) or "отмена ввода"), file=sys.stderr)
    except Exception:
        # Some API/library exceptions embed credentials or a complete config.
        print("\nНепредвиденная ошибка. Подробности не печатаются, чтобы не раскрыть секреты.", file=sys.stderr)
    if sys.platform == "linux" and LOG.is_dir():
        print(f"Приватные журналы: {LOG}. Если установка началась, её файлы сохранены для разбора.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
