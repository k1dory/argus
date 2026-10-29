#!/bin/sh
# Обёртка перед caddy run: приводит MCP_ALLOWED_NETS к виду, который принимает
# матчер remote_ip, чтобы опечатка в списке сетей MCP не уронила весь Caddyfile
# (вместе с консолью :8443 и вебхуками :8089).
#
# - разделители: пробел и запятая (остальные списки в .env — через запятую);
# - каждый элемент — IPv4/IPv6 адрес или CIDR, иначе он отбрасывается с
#   предупреждением в журнал (отброс только сужает доступ);
# - пустой список — 127.0.0.1/32;
# - шлюз сети Docker добавляется всегда: соединение с самого хоста на
#   опубликованный порт приходит в контейнер через docker-proxy с адреса шлюза,
#   а не 127.0.0.1, так что без него «только localhost» означало бы «никому».
#   На Docker Desktop (macOS/Windows) так приходят все клиенты — там
#   MCP_ALLOWED_NETS не отличает хост от сети; ограничивайте MCP_BIND.
set -eu

ip_ok() {
	case "$1" in
	*[!0-9a-fA-F.:/]*) return 1 ;;
	esac
	case "$1" in
	*.*)
		addr="${1%%/*}"; pfx="${1#*/}"; [ "$pfx" = "$1" ] && pfx=32
		case "$pfx" in *[!0-9]*) return 1 ;; esac
		[ "$pfx" -le 32 ] || return 1
		echo "$addr" | awk -F. 'NF!=4{exit 1} {for(i=1;i<=4;i++) if($i=="" || $i>255) exit 1}'
		;;
	*:*)
		pfx="${1#*/}"; [ "$pfx" = "$1" ] && pfx=128
		case "$pfx" in *[!0-9]*) return 1 ;; esac
		[ "$pfx" -le 128 ]
		;;
	*) return 1 ;;
	esac
}

nets=""
for n in $(printf '%s' "${MCP_ALLOWED_NETS:-}" | tr ',' ' '); do
	if ip_ok "$n"; then
		nets="$nets $n"
	else
		echo "caddy-entrypoint: MCP_ALLOWED_NETS — «$n» не адрес и не CIDR, пропущен" >&2
	fi
done
[ -n "$nets" ] || nets=" 127.0.0.1/32"

# Шлюз по умолчанию — из /proc/net/route (поле Gateway, hex little-endian).
gw=$(awk '$2=="00000000" && $3!="00000000" {print $3; exit}' /proc/net/route 2>/dev/null || true)
if [ -n "$gw" ]; then
	gw_ip=$(printf '%d.%d.%d.%d' "0x${gw#??????}" "0x$(echo "$gw" | cut -c5-6)" "0x$(echo "$gw" | cut -c3-4)" "0x$(echo "$gw" | cut -c1-2)")
	case " $nets " in *" $gw_ip/32 "*) ;; *) nets="$nets $gw_ip/32" ;; esac
fi

export MCP_ALLOWED_NETS="${nets# }"
echo "caddy-entrypoint: MCP_ALLOWED_NETS=$MCP_ALLOWED_NETS" >&2
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
