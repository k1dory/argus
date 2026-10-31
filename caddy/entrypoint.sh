#!/bin/sh
# Обёртка перед caddy run: приводит MCP_ALLOWED_NETS к виду, который принимает
# матчер remote_ip, чтобы опечатка в списке сетей MCP не уронила весь Caddyfile
# (вместе с консолью :8443 и вебхуками :8089).
#
# - разделители: пробел и запятая (остальные списки в .env — через запятую);
# - каждый элемент — IPv4/IPv6 адрес или CIDR в той же строгости, что у Go netip
#   (октеты 0–255 без ведущих нулей, IPv6 — не больше восьми групп по 1–4 hex и
#   одно «::», префикс 0–32/0–128); остальное отбрасывается с предупреждением
#   (отброс только сужает доступ);
# - пустой список — 127.0.0.1/32;
# - шлюз сети Docker (MCP_ALLOW_HOST). Клиент с самого хоста приходит на
#   опубликованный порт через docker-proxy с адреса шлюза, а не 127.0.0.1. Но в
#   rootless Docker, при userland-proxy и на Docker Desktop с адреса шлюза приходят
#   ВСЕ клиенты, и разрешённый шлюз превращает список сетей в «всем». Поэтому:
#     MCP_ALLOW_HOST=1 — шлюз разрешён; =0 — нет;
#     не задано — разрешён, только если порт опубликован на loopback (MCP_BIND
#     127.0.0.1/::1, по умолчанию): тогда до порта дотягивается лишь сам хост.
set -eu

ipv4_ok() { # адрес без префикса
	printf '%s' "$1" | awk -F. 'NF!=4 {exit 1}
		{for (i = 1; i <= 4; i++) if ($i !~ /^(0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$/) exit 1}'
}

ipv6_ok() { # адрес без префикса; встроенный IPv4 в хвосте не поддерживается — Caddy его тоже не ждёт
	printf '%s' "$1" | awk '
		{ s = $0 }
		s !~ /^[0-9a-fA-F:]+$/ { exit 1 }
		{ n = gsub(/::/, "&", s) }
		n > 1 { exit 1 }
		s ~ /:::/ { exit 1 }
		n == 0 && (s ~ /^:/ || s ~ /:$/) { exit 1 }
		n == 1 && ((s ~ /^:[^:]/) || (s ~ /[^:]:$/)) { exit 1 }
		{
			t = s; sub(/::/, ":", t); sub(/^:/, "", t); sub(/:$/, "", t)
			g = (t == "") ? 0 : split(t, p, ":")
			for (i = 1; i <= g; i++) if (length(p[i]) < 1 || length(p[i]) > 4) exit 1
			if (n == 1 && g > 7) exit 1
			if (n == 0 && g != 8) exit 1
		}'
}

prefix_ok() { # $1 — префикс, $2 — максимум
	case "$1" in '' | *[!0-9]*) return 1 ;; 0) return 0 ;; 0*) return 1 ;; esac
	[ "$1" -le "$2" ]
}

ip_ok() {
	addr="${1%%/*}"
	case "$1" in
	*/) return 1 ;;
	*/*) pfx="${1#*/}" ;;
	*) pfx="" ;;
	esac
	case "$pfx" in */*) return 1 ;; esac
	case "$addr" in
	*:*)
		ipv6_ok "$addr" || return 1
		[ -z "$pfx" ] || prefix_ok "$pfx" 128
		;;
	*.*)
		ipv4_ok "$addr" || return 1
		[ -z "$pfx" ] || prefix_ok "$pfx" 32
		;;
	*) return 1 ;;
	esac
}

# Самопроверка: entrypoint.sh --check ADDR… печатает ok/bad по каждому (тесты, отладка).
if [ "${1:-}" = "--check" ]; then
	shift
	for a in "$@"; do if ip_ok "$a"; then echo "ok  $a"; else echo "bad $a"; fi; done
	exit 0
fi

nets=""
for n in $(printf '%s' "${MCP_ALLOWED_NETS:-}" | tr ',' ' '); do
	if ip_ok "$n"; then
		nets="$nets $n"
	else
		echo "caddy-entrypoint: MCP_ALLOWED_NETS — «$n» не адрес и не CIDR, пропущен" >&2
	fi
done
[ -n "$nets" ] || nets=" 127.0.0.1/32"

allow_host="${MCP_ALLOW_HOST:-}"
if [ -z "$allow_host" ]; then
	case "${MCP_BIND:-127.0.0.1}" in
	127.* | ::1 | "[::1]" | localhost) allow_host=1 ;;
	*) allow_host=0 ;;
	esac
fi
case "$allow_host" in
1 | true | yes | on)
	# Шлюз по умолчанию — из /proc/net/route (поле Gateway, hex little-endian).
	gw=$(awk '$2=="00000000" && $3!="00000000" {print $3; exit}' /proc/net/route 2>/dev/null || true)
	if [ -n "$gw" ]; then
		gw_ip=$(printf '%d.%d.%d.%d' "0x${gw#??????}" "0x$(echo "$gw" | cut -c5-6)" "0x$(echo "$gw" | cut -c3-4)" "0x$(echo "$gw" | cut -c1-2)")
		case " $nets " in *" $gw_ip/32 "*) ;; *) nets="$nets $gw_ip/32" ;; esac
		echo "caddy-entrypoint: шлюз Docker $gw_ip разрешён для MCP (клиенты с самого хоста; MCP_ALLOW_HOST=0 — запретить)" >&2
	fi
	;;
*)
	echo "caddy-entrypoint: шлюз Docker для MCP не разрешён (MCP_BIND=${MCP_BIND:-127.0.0.1}, MCP_ALLOW_HOST=${MCP_ALLOW_HOST:-}): клиенты с самого хоста — через MCP_ALLOW_HOST=1, если Docker сохраняет адреса клиентов" >&2
	;;
esac

export MCP_ALLOWED_NETS="${nets# }"
echo "caddy-entrypoint: MCP_ALLOWED_NETS=$MCP_ALLOWED_NETS" >&2
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
