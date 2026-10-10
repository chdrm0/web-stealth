#!/usr/bin/env bash
# One-time setup of this bundle on a machine that already runs the harness.
#
#   ./install.sh            set everything up
#   ./install.sh doctor     check an existing setup, change nothing
#
# What it does, in order: creates the sidecar's Python environment from the
# lockfile, installs the bundle into a harness profile, then reports what is
# still missing for this machine (a browser, a proxy, a captcha key). It never
# writes a secret: `.env` is only read, never created or filled in.
#
# Deliberately not automated: the profile restart, the interactive cookie
# harvest, and anything that touches the VPN/xray configuration. Those are the
# steps a person should see happen.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${DSH_PROFILE:-web}"
DSH_HOME_DIR="${DSH_HOME:-$HOME/.dsh}"
BROWSER="${STEALTH_BROWSER:-/usr/bin/brave}"
# Read from the bundle's own patch, which is the authority for the proxy.
PROXY_LINE="$(sed -n 's/^[[:space:]]*proxy:[[:space:]]*//p' "$HERE/cordis.patch.yml" | head -1)"
PROXY_HOSTPORT="${PROXY_LINE#*://}"

say() { printf '%s\n' "$*"; }
bad() { printf 'MISSING  %s\n' "$*" >&2; }
good() { printf 'ok       %s\n' "$*"; }

# The bundle patch pins no paths: the plugin derives the sidecar directory and its
# interpreter from where the bundle itself sits. So the installer has nothing to
# rewrite — it only checks that the profile can actually see this copy's venv,
# because a sidecar that cannot start is not a loud failure: retrieval just stops
# being stealthed.
check_sidecar_visible() {
	local seen="$DSH_HOME_DIR/profiles/$PROFILE/node_modules/@local/web-stealth/fetchd/.venv/bin/python"
	[ -x "$seen" ] && good "profile sees the sidecar interpreter: $seen" || { bad "the profile's copy of the bundle has no venv at $seen — install the bundle as a link to this directory, or build a venv there"; return 1; }
}

doctor() {
	local problems=0
	command -v dsh >/dev/null 2>&1 && good "dsh on PATH ($(dsh --version 2>/dev/null | head -1))" || { bad "dsh is not on PATH"; problems=$((problems + 1)); }
	command -v uv >/dev/null 2>&1 && good "uv on PATH" || { bad "uv is not on PATH — the sidecar environment cannot be built"; problems=$((problems + 1)); }
	[ -x "$HERE/fetchd/.venv/bin/python" ] && good "sidecar venv: $HERE/fetchd/.venv" || { bad "no sidecar venv — run: $0"; problems=$((problems + 1)); }
	# The same families the plugin offers on the settings page. One line per family:
	# /usr/bin/brave is a wrapper that execs /opt/brave-bin/brave, and listing both
	# as if they were two browsers would be noise.
	local browser_family="" browser_paths="" candidate family
	for candidate in /usr/bin/brave /opt/brave-bin/brave /usr/bin/google-chrome /usr/bin/google-chrome-stable /usr/bin/chromium /usr/bin/chromium-browser /snap/bin/chromium /usr/bin/microsoft-edge; do
		[ -x "$candidate" ] || continue
		family="${candidate##*/}"
		case "$family" in brave*) family=brave ;; google-chrome*) family=chrome ;; chromium*) family=chromium ;; edge*) family=edge ;; esac
		case " $browser_family " in *" $family "*) continue ;; esac
		browser_family="$browser_family $family"
		browser_paths="$browser_paths $candidate"
		good "browser: $candidate"
	done
	# Only worth a line of its own if it is somewhere the loop did not already look.
	if [ -x "$BROWSER" ]; then
		case " $browser_paths " in
			*" $BROWSER "*) ;;
			*) good "browser: $BROWSER (STEALTH_BROWSER)" ;;
		esac
	fi
	[ -n "$browser_family" ] || { bad "no Chromium-family browser at the usual paths — name one as \`browserExecutable:\` in the plugin config"; problems=$((problems + 1)); }
	if [ -n "$PROXY_HOSTPORT" ]; then
		local host="${PROXY_HOSTPORT%%:*}" port="${PROXY_HOSTPORT##*:}"
		if command -v timeout >/dev/null 2>&1 && timeout 3 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
			good "proxy $host:$port accepts a connection"
		else
			bad "proxy $host:$port is not listening — start the VPN, or change \`proxy:\` in $HERE/cordis.patch.yml"
			problems=$((problems + 1))
		fi
	elif [ -n "$PROXY_LINE" ]; then
		say "note     no exit configured — the machine goes out as itself, and the browser refuses requests aimed at it"
	else
		bad "no \`proxy:\` row in $HERE/cordis.patch.yml"
		problems=$((problems + 1))
	fi
	if [ -f "$HERE/.env" ] || [ -f "$(dirname "$HERE")/.env" ]; then
		good "a .env is present (captcha key is optional; retrieval works without it)"
	else
		say "note     no .env beside the bundle — captcha solving stays off"
	fi
	# The profile holds the bundle as a link to this directory, so the entry is a
	# directory, not a file.
	[ -d "$DSH_HOME_DIR/profiles/$PROFILE/node_modules/@local/web-stealth" ] && good "bundle installed in profile '$PROFILE'" || { bad "bundle not installed in profile '$PROFILE' — run: $0"; problems=$((problems + 1)); }
	[ -d "$DSH_HOME_DIR/profiles/$PROFILE/node_modules/@local/web-stealth-ui" ] && good "settings page installed in profile '$PROFILE'" || { bad "settings page not installed in profile '$PROFILE' — run: $0"; problems=$((problems + 1)); }
	[ -d "$DSH_HOME_DIR/web-stealth/jar" ] && good "cookie jar: $DSH_HOME_DIR/web-stealth/jar" || say "note     no cookie jar yet — sign in once with: (cd $HERE/fetchd && ./.venv/bin/python -m fetchd.harvest)"
	return "$problems"
}

if [ "${1:-}" = "doctor" ]; then
	problems=0
	doctor || problems=$?
	if [ "$problems" -gt 0 ]; then
		say ""
		say "$problems problem(s) — see the MISSING lines above."
		exit 1
	fi
	exit 0
fi

say "bundle:   $HERE"
say "profile:  $PROFILE"

command -v uv >/dev/null 2>&1 || { bad "uv is required to build the sidecar environment"; exit 1; }
say ""
say "sidecar environment (uv, from uv.lock)"
(cd "$HERE/fetchd" && uv sync --frozen)

say ""
say "bundle into the profile"
command -v dsh >/dev/null 2>&1 || { bad "dsh is required to install the bundle"; exit 1; }
[ -d "$HERE/../web-stealth-ui" ] || { bad "the settings page (@local/web-stealth-ui) must sit next to this bundle — copy the whole project directory, not just web-stealth/"; exit 1; }
# Two rows, two packages: the provider (retrieval, browser tools) and its settings
# page. The page is a separate package because mounting the provider twice would
# start a second sidecar.
dsh plugin --profile "$PROFILE" add "$HERE"
dsh plugin --profile "$PROFILE" add "$HERE/../web-stealth-ui"

say ""
say "the sidecar, as the profile will look for it"
check_sidecar_visible || true

say ""
say "checking"
doctor || true

cat <<EOF

Next, by hand:
  1. Restart the profile — the bundle's JS and its patch are read at startup.
  2. Sign in once, in a browser you can see:
       cd $HERE/fetchd && ./.venv/bin/python -m fetchd.harvest
  3. If the exit is not the one in cordis.patch.yml, change the \`proxy:\` row
     there (or pick it in the plugin's settings page) and restart again.
EOF
