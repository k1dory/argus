#!/usr/bin/env bash
# Замер пропускной способности коллектора: шлёт N строк CEF по UDP на :5514
# и считает принятые события по /metrics. Честная цифра для лендинга.
#   ./scripts/bench-ingest.sh [N=200000] [HOST=127.0.0.1]
set -euo pipefail
N="${1:-200000}"; HOST="${2:-127.0.0.1}"
M="http://$HOST:8088/metrics"
before=$(curl -sS "$M" | awk '/^argus_collector_events_total/ {print $2}')
start=$(python3 -c 'import time;print(time.time())')
python3 - "$N" "$HOST" <<'PY'
import socket, sys, time
n, host = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
line = ('<134>1 2026-09-06T10:00:00Z fw-01 CheckPoint - - - CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Accept|Firewall|0|'
        'rt=1757066138000 src=10.20.4.%d spt=%d dst=10.20.5.7 dpt=445 proto=TCP suser=svc-backup act=Accept externalId=%d dvchost=fw-01')
for i in range(n):
    s.sendto((line % (i % 250 + 1, 40000 + i % 20000, i)).encode(), (host, 5514))
    if i % 2000 == 0:
        time.sleep(0.001)  # не забить UDP-буфер ядра на localhost
PY
# ждём, пока очередь коллектора дойдёт до базы
for _ in $(seq 1 60); do
  after=$(curl -sS "$M" | awk '/^argus_collector_events_total/ {print $2}')
  q=$(curl -sS "$M" | awk '/^argus_collector_queue_length/ {print $2}')
  [ "${q:-0}" -eq 0 ] && [ $((after - before)) -ge $((N * 95 / 100)) ] && break
  sleep 1
done
end=$(python3 -c 'import time;print(time.time())')
recv=$((after - before))
dropped=$(curl -sS "$M" | awk '/^argus_collector_events_dropped_total/ {print $2}')
python3 - "$recv" "$N" "$start" "$end" "$dropped" <<'PY'
import sys
recv, n, start, end, dropped = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])
print(f"отправлено {n}, принято {recv} ({100*recv/n:.1f} %), отброшено очередью {dropped}, {end-start:.1f} с → {recv/(end-start):.0f} EPS")
PY
