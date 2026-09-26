#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: run as root (sudo)." >&2
  exit 1
fi

DS="${DS:-/opt/complianceascode/scap-security-guide-0.1.82/ssg-ubuntu2404-ds.xml}"
PROFILE="${PROFILE:-xccdf_org.ssgproject.content_profile_cis_level1_server}"
OUT_BASE="${OUT_BASE:-/var/lib/openscap-audit}"
CPU_QUOTA="${CPU_QUOTA:-200%}"
MEMORY_HIGH="${MEMORY_HIGH:-3584M}"
MEMORY_MAX="${MEMORY_MAX:-4G}"
RUNTIME_MAX="${RUNTIME_MAX:-2h}"
HOST_CPU_KILL_PCT="${HOST_CPU_KILL_PCT:-90}"
HOST_MEM_KILL_PCT="${HOST_MEM_KILL_PCT:-90}"
FILESYSTEM_KILL_PCT="${FILESYSTEM_KILL_PCT:-90}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-5}"

command -v oscap >/dev/null
command -v systemd-run >/dev/null
systemctl is-system-running >/dev/null
test -r "$DS"

for number in "$HOST_CPU_KILL_PCT" "$HOST_MEM_KILL_PCT" "$FILESYSTEM_KILL_PCT" "$SAMPLE_INTERVAL"; do
  [[ "$number" =~ ^[0-9]+$ ]] || { echo "ERROR: invalid numeric setting: $number" >&2; exit 1; }
done

install -d -o root -g root -m 0700 "$OUT_BASE"

FREE_KB="$(df -Pk "$OUT_BASE" | awk 'NR==2 {print $4}')"
FS_USED="$(df -P "$OUT_BASE" | awk 'NR==2 {gsub(/%/,"",$5); print $5}')"
if (( FREE_KB < 5242880 || FS_USED >= FILESYSTEM_KILL_PCT )); then
  echo "ERROR: output filesystem must have at least 5 GiB free and usage below ${FILESYSTEM_KILL_PCT}%." >&2
  exit 1
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOST="$(hostname -s | tr -cd '[:alnum:]._-')"
OUT_DIR="$OUT_BASE/${HOST}-ubuntu2404-cis-level1-server-$STAMP"
UNIT="openscap-cis-${STAMP,,}"
install -d -o root -g root -m 0700 "$OUT_DIR"

cat > "$OUT_DIR/manifest.txt" <<EOF
started_utc=$STAMP
hostname=$HOST
os_release=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2-)
datastream=$DS
datastream_sha256=$(sha256sum "$DS" | awk '{print $1}')
profile=$PROFILE
cpu_quota=$CPU_QUOTA
memory_high=$MEMORY_HIGH
memory_max=$MEMORY_MAX
memory_swap_max=0
runtime_max=$RUNTIME_MAX
host_cpu_kill_pct=$HOST_CPU_KILL_PCT
host_mem_kill_pct=$HOST_MEM_KILL_PCT
filesystem_kill_pct=$FILESYSTEM_KILL_PCT
sample_interval_seconds=$SAMPLE_INTERVAL
EOF

printf 'timestamp_utc,cpu_total_pct,memory_total_pct,filesystem_used_pct\n' > "$OUT_DIR/resource-usage.csv"

systemd-run \
  --unit="$UNIT" \
  --property=Type=exec \
  --property="CPUQuota=$CPU_QUOTA" \
  --property="MemoryHigh=$MEMORY_HIGH" \
  --property="MemoryMax=$MEMORY_MAX" \
  --property=MemorySwapMax=0 \
  --property=KillMode=control-group \
  --property=TimeoutStopSec=5s \
  --property=SendSIGKILL=yes \
  --property=Nice=10 \
  --property=IOSchedulingClass=idle \
  --property="RuntimeMaxSec=$RUNTIME_MAX" \
  /usr/bin/oscap xccdf eval \
    --profile "$PROFILE" \
    --oval-results \
    --results-arf "$OUT_DIR/results-arf.xml" \
    --report "$OUT_DIR/report.html" \
    "$DS"

read_cpu_sample() {
  local label user nice system idle iowait irq softirq steal guest guest_nice
  read -r label user nice system idle iowait irq softirq steal guest guest_nice < /proc/stat
  CPU_IDLE=$((idle + iowait))
  CPU_TOTAL=$((user + nice + system + idle + iowait + irq + softirq + steal))
}

ABORTED=0
read_cpu_sample
PREV_IDLE=$CPU_IDLE
PREV_TOTAL=$CPU_TOTAL

while systemctl is-active --quiet "$UNIT"; do
  sleep "$SAMPLE_INTERVAL"
  read_cpu_sample
  DELTA_IDLE=$((CPU_IDLE - PREV_IDLE))
  DELTA_TOTAL=$((CPU_TOTAL - PREV_TOTAL))
  if (( DELTA_TOTAL > 0 )); then
    CPU_PCT=$((100 * (DELTA_TOTAL - DELTA_IDLE) / DELTA_TOTAL))
  else
    CPU_PCT=0
  fi
  PREV_IDLE=$CPU_IDLE
  PREV_TOTAL=$CPU_TOTAL

  MEM_PCT="$(awk '
    /MemTotal:/ {total=$2}
    /MemAvailable:/ {available=$2}
    END {printf "%d", 100 * (total - available) / total}
  ' /proc/meminfo)"
  FS_PCT="$(df -P "$OUT_BASE" | awk 'NR==2 {gsub(/%/,"",$5); print $5}')"
  NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s,%s,%s,%s\n' "$NOW" "$CPU_PCT" "$MEM_PCT" "$FS_PCT" >> "$OUT_DIR/resource-usage.csv"

  if (( CPU_PCT >= HOST_CPU_KILL_PCT || MEM_PCT >= HOST_MEM_KILL_PCT || FS_PCT >= FILESYSTEM_KILL_PCT )); then
    printf 'Aborted at %s: host CPU=%s%%, host memory=%s%%, output filesystem=%s%%.\n' \
      "$NOW" "$CPU_PCT" "$MEM_PCT" "$FS_PCT" | tee "$OUT_DIR/ABORTED-HOST-RESOURCE"
    systemctl kill --kill-whom=main --signal=SIGKILL "$UNIT" || true
    systemctl stop "$UNIT" || true
    ABORTED=1
    break
  fi
done

sleep 1
EXIT_CODE="$(systemctl show "$UNIT" --property=ExecMainStatus --value 2>/dev/null || true)"
RESULT="$(systemctl show "$UNIT" --property=Result --value 2>/dev/null || true)"
printf '%s\n' "${EXIT_CODE:-unknown}" > "$OUT_DIR/oscap-exit-code"
printf 'systemd_result=%s\n' "${RESULT:-unknown}" >> "$OUT_DIR/manifest.txt"
journalctl -u "$UNIT" --no-pager > "$OUT_DIR/journal.log"
systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true

(
  cd "$OUT_DIR"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' \
    | sort -z \
    | xargs -0r sha256sum > SHA256SUMS
)

echo "Output directory: $OUT_DIR"
echo "OpenSCAP exit code: ${EXIT_CODE:-unknown}"
echo "systemd result: ${RESULT:-unknown}"

if (( ABORTED == 1 )); then
  echo "ERROR: audit was aborted because a host resource threshold was reached." >&2
  exit 90
fi

if [[ "$EXIT_CODE" == "0" || "$EXIT_CODE" == "2" ]]; then
  exit 0
fi

echo "ERROR: OpenSCAP failed; inspect $OUT_DIR/journal.log" >&2
exit 1

