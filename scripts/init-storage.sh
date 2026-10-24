#!/usr/bin/env sh
# Данные ClickHouse и бэкапы — на отдельном диске, как /var/ossec у менеджера
# Wazuh. Запускается ОДИН РАЗ до первого `make up`: создаёт именованные тома
# compose поверх каталогов на нужном диске. Если тома уже есть (стенд поднимали
# раньше) — сначала `docker compose down -v` или перенос данных вручную.
#
#   ./scripts/init-storage.sh /srv/argus            # → /srv/argus/clickhouse, /srv/argus/backups
#   ./scripts/init-storage.sh /srv/argus /mnt/bkp   # бэкапы на другой диск
set -eu
base="${1:?каталог данных, например /srv/argus}"
bkp="${2:-$base/backups}"
project="${COMPOSE_PROJECT_NAME:-$(basename "$(cd "$(dirname "$0")/.." && pwd)")}"

mk() { # имя тома, каталог
  mkdir -p "$2"
  if docker volume inspect "$1" >/dev/null 2>&1; then
    echo "том $1 уже существует — пропускаю (device: $(docker volume inspect -f '{{index .Options "device"}}' "$1"))"
    return
  fi
  docker volume create --driver local --opt type=none --opt o=bind --opt device="$2" "$1" >/dev/null
  echo "том $1 → $2"
}
mk "${project}_clickhouse-data" "$base/clickhouse"
mk "${project}_clickhouse-backups" "$bkp"
echo "готово: теперь make up"
