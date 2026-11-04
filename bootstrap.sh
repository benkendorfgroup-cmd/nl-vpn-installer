#!/usr/bin/env bash
# Download a pinned installer; never contains VPS/proxy credentials.
set -euo pipefail

INSTALLER_URL='https://raw.githubusercontent.com/benkendorfgroup-cmd/nl-vpn-installer/v1.1.0/install.py'
INSTALLER_SHA256='794592b0360346cbf692b3489f2c8e436af9bab2d9ac373c27acc3cd40ed5f13'

fail() { printf '%s\n' "$*" >&2; return 1; }

supports_debian() { [[ ${1:-} == debian && ( ${2:-} == 12 || ${2:-} == 13 ) ]]; }

check_system() {
    [[ $(uname -s) == Linux ]] || { fail 'Запускай на сервере Debian 12/13 через SSH.'; return 1; }
    [[ $EUID -eq 0 ]] || { fail 'Нужны права root. Запусти через sudo bash bootstrap.sh.'; return 1; }
    [[ -t 0 && -t 1 ]] || { fail 'Нужен обычный интерактивный SSH-терминал.'; return 1; }
    [[ -f /etc/os-release && -d /run/systemd/system ]] || { fail 'Нужна Debian 12/13 с systemd.'; return 1; }
    . /etc/os-release
    supports_debian "${ID:-}" "${VERSION_ID:-}" || { fail 'Нужна Debian 12 или 13.'; return 1; }
    case $(uname -m) in x86_64|aarch64) ;; *) fail 'Нужна архитектура amd64 или arm64.'; return 1 ;; esac
    local path
    for path in /opt/nl-vpn /var/lib/nl-vpn /var/log/nl-vpn /root/nl-vpn-access \
        /etc/systemd/system/nl-vpn.service /etc/systemd/system/nl-vpn.service.d \
        /etc/x-ui /usr/local/x-ui /opt/x-ui /etc/systemd/system/x-ui.service; do
        [[ ! -e $path && ! -L $path ]] || { fail "Уже существует $path. Повторная установка отменена."; return 1; }
    done
    if getent passwd nl-vpn >/dev/null || getent group nl-vpn >/dev/null; then
        fail 'Учётная запись nl-vpn уже существует. Ничего не перезаписываю.'
        return 1
    fi
}

prepare_packages() {
    local package status
    local -a missing=()
    for package in python3 curl ca-certificates iproute2; do
        status=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)
        [[ $status == 'install ok installed' ]] || missing+=("$package")
    done
    if ((${#missing[@]})); then
        printf 'Подготавливаю необходимые пакеты: %s\n' "${missing[*]}"
        apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update
        DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get \
            -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=60 \
            install --yes --no-install-recommends --no-upgrade --no-remove "${missing[@]}"
    fi
}

fetch_installer() {
    local folder=$1
    [[ $INSTALLER_SHA256 =~ ^[a-f0-9]{64}$ ]] || { fail 'В комплекте не задана контрольная сумма.'; return 1; }
    curl -q --noproxy '*' --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 120 --max-filesize 262144 \
        "$INSTALLER_URL" --output "$folder/install.py.part" || return 1
    printf '%s  %s\n' "$INSTALLER_SHA256" "$folder/install.py.part" | sha256sum --check --status || {
        fail 'Скачанный установщик не совпал с проверенной версией. Запуск отменён.'; return 1;
    }
    mv -- "$folder/install.py.part" "$folder/install.py"
}

cleanup() {
    # Only our two known files, never a recursive delete or somebody else's data.
    if [[ ${workdir:-} == /root/nl-vpn-bootstrap.* && -d $workdir && ! -L $workdir ]]; then
        rm -f -- "$workdir/install.py" "$workdir/install.py.part"
        rmdir -- "$workdir" 2>/dev/null || true
    fi
}

main() {
    check_system
    prepare_packages
    umask 077
    workdir=$(mktemp -d /root/nl-vpn-bootstrap.XXXXXXXX)
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    printf '%s\n' 'Скачиваю установщик с GitHub и проверяю его целостность…'
    fetch_installer "$workdir"
    # Keep the terminal as stdin: passwords never enter a pipe or command arguments.
    python3 "$workdir/install.py" --quick
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
