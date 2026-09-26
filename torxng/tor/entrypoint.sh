#!/bin/sh
# Entry point of the tor container.
#
# 1. Copy the torrc template to /tmp (tmpfs; the root filesystem is read-only
#    and the image runs as the unprivileged "tor" user).
# 2. Onion service proof-of-work defense (proposal 327): enabled only if this
#    tor build contains the "pow" module (tor --list-modules), otherwise tor
#    would refuse the option.
# 3. ControlPort: enabled only if a password is configured, then always
#    protected by HashedControlPassword (only the salted hash is written to
#    the config file; the plaintext never touches the disk) and bound to
#    127.0.0.1 INSIDE this container: neither SearXNG nor nginx can reach it.
#    It is used only by the operator (torxng/benchmark/show_circuits.py via
#    "docker compose exec tor"). The ControlPort grants full control over
#    tor (e.g. pinning guards, reading the circuit paths), which would enable
#    guard discovery attacks against the onion service if a web-facing
#    component held the password.
#    Password source, in this order:
#      a) the Compose secret file /run/secrets/tor_control_password
#         (torxng/secrets/tor_control_password on the host); not visible in
#         "docker inspect" or in the container environment
#      b) fallback, only if that file does not exist: the environment
#         variable TOR_CONTROL_PASSWORD (visible in "docker inspect"; the
#         TorXNG docker-compose.yml does not set it)
# 4. exec tor, so it runs as PID 1 and receives SIGTERM from "docker stop".
set -eu

TEMPLATE=/etc/tor/torrc.template
TORRC=/tmp/torrc

cp "$TEMPLATE" "$TORRC"

# The template ends with the HiddenService* block; per-service options must
# follow their HiddenServiceDir, so the PoW line is appended first.
if tor --list-modules 2>/dev/null | grep -q '^pow: yes'; then
    echo "HiddenServicePoWDefensesEnabled 1" >>"$TORRC"
    echo "tor-entrypoint: onion service PoW defense enabled (pow module present)"
else
    echo "tor-entrypoint: onion service PoW defense NOT available in this tor build (pow module missing)"
fi

SECRET_FILE=/run/secrets/tor_control_password
PASSWORD=""
PASSWORD_SOURCE=""
if [ -d "$SECRET_FILE" ]; then
    # Docker creates an empty directory in place of a missing bind-mount source.
    echo "tor-entrypoint: $SECRET_FILE is a directory: torxng/secrets/tor_control_password did not exist when the stack was created (Docker created a directory in its place). Remove that directory on the host, create the file (see torxng/README.md) and recreate the tor container." >&2
elif [ -e "$SECRET_FILE" ]; then
    if [ ! -r "$SECRET_FILE" ]; then
        echo "tor-entrypoint: $SECRET_FILE is not readable by $(id -un) (uid $(id -u)); on Linux make the host file readable for uid $(id -u), e.g. chmod 0644 (keep torxng/secrets/ at mode 0700)" >&2
        exit 1
    fi
    # strip CR/LF (files written by editors, "echo" or PowerShell)
    PASSWORD=$(tr -d '\r\n' <"$SECRET_FILE")
    PASSWORD_SOURCE="secret file $SECRET_FILE"
elif [ -n "${TOR_CONTROL_PASSWORD:-}" ]; then
    PASSWORD=$TOR_CONTROL_PASSWORD
    PASSWORD_SOURCE="environment variable TOR_CONTROL_PASSWORD (fallback: $SECRET_FILE does not exist; the variable is visible in docker inspect)"
fi
unset TOR_CONTROL_PASSWORD

if [ -n "$PASSWORD" ]; then
    # Accept only a plain token: no quotes/backslashes/whitespace (they would
    # need escaping in the control protocol) and no stray bytes such as the
    # NULs and BOM of a UTF-16 file written by Windows PowerShell 5.
    if [ "${#PASSWORD}" -lt 16 ] || [ -n "$(printf '%s' "$PASSWORD" | tr -d 'A-Za-z0-9._~+=/-')" ]; then
        echo "tor-entrypoint: invalid ControlPort password from $PASSWORD_SOURCE: use at least 16 characters out of A-Z a-z 0-9 . _ ~ + = / - (e.g. openssl rand -hex 32) and save the file as ASCII/UTF-8" >&2
        exit 1
    fi
    # "tor --hash-password" may print log lines first; the hash is the last line.
    HASHED=$(tor --hash-password "$PASSWORD" | tail -n 1)
    case "$HASHED" in
        16:*) ;;
        *)
            echo "tor-entrypoint: could not hash the ControlPort password" >&2
            exit 1
            ;;
    esac
    {
        echo ""
        echo "# added by tor-entrypoint.sh (ControlPort password configured)"
        echo "ControlPort 127.0.0.1:9051"
        echo "HashedControlPassword $HASHED"
    } >>"$TORRC"
    echo "tor-entrypoint: ControlPort enabled on 127.0.0.1:9051 inside the tor container (password protected, password from $PASSWORD_SOURCE)"
    unset HASHED
else
    echo "tor-entrypoint: no ControlPort password ($SECRET_FILE missing or empty, TOR_CONTROL_PASSWORD not set), ControlPort disabled"
fi

unset PASSWORD PASSWORD_SOURCE SECRET_FILE

exec tor -f "$TORRC"
