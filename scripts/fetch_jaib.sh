#!/usr/bin/env bash
# Fetch the official Jaib Digital Wallet APK (com.ahd.jaib) from e-jaib.com
# and save it as apk/jaib-digital-wallet.apk
set -uo pipefail

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
OUT_DIR="apk"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/jaib-digital-wallet.apk"
LOG="fetch.log"
: > "$LOG"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

candidates=()

# 1) Parse official download pages for any .apk links
for page in \
  "https://e-jaib.com/d.html" \
  "https://e-jaib.com/D.html" \
  "https://e-jaib.com/Download.html" \
  "https://e-jaib.com/DLma.html" \
  "https://e-jaib.com/Download" \
  "https://e-jaib.com/" \
  "https://www.e-jaib.com/" ; do
  log "-- fetch page: $page"
  html=$(curl -sL -A "$UA" --max-time 30 "$page" || true)
  log "   body bytes: ${#html}"
  while read -r u; do
    [ -n "$u" ] || continue
    case "$u" in
      http*) candidates+=("$u") ;;
      /*)    candidates+=("https://e-jaib.com$u") ;;
    esac
  done < <(printf '%s' "$html" | grep -Eo '([a-zA-Z0-9_/?=&.%+:#~-]+\.apk)' | sort -u)
done

# 2) Plausible direct paths on the official server
for p in \
  "/jaib.apk" "/Jaib.apk" "/JAIB.apk" "/app.apk" "/App.apk" \
  "/app/jaib.apk" "/app/Jaib.apk" "/app/app.apk" \
  "/apk/jaib.apk" "/apk/Jaib.apk" "/apk/app.apk" \
  "/download/jaib.apk" "/download/Jaib.apk" "/download/app.apk" \
  "/downloads/Jaib.apk" "/uploads/Jaib.apk" "/files/Jaib.apk" \
  "/android/Jaib.apk" "/apps/Jaib.apk" "/client/Jaib.apk" \
  "/release/Jaib.apk" "/releases/Jaib.apk" "/download.apk" "/Download.apk" \
  "/jaib/jaib.apk" "/jaib.apk?download=1" ; do
  candidates+=("https://e-jaib.com$p")
done

mapfile -t candidates < <(printf '%s\n' "${candidates[@]}" | sort -u)
log "Total candidate URLs: ${#candidates[@]}"

found=""
for u in "${candidates[@]}"; do
  log "-- try: $u"
  code=$(curl -sL -A "$UA" --max-time 60 -o /tmp/probe.bin -w "%{http_code}" "$u" || echo 000)
  size=$(stat -c%s /tmp/probe.bin 2>/dev/null || echo 0)
  magic=$(head -c 4 /tmp/probe.bin | od -An -tx1 | tr -d ' \n')
  log "   code=$code size=$size magic=$magic"
  if [ "$code" = "200" ] && [ "$size" -gt 5000000 ] && [ "$magic" = "504b0304" ]; then
    found="$u"
    mv /tmp/probe.bin "$OUT"
    break
  fi
done

if [ -z "$found" ]; then
  log "FAILED: no valid APK found from any source"
  exit 1
fi

log "SUCCESS: $found -> $OUT"
sha256sum "$OUT" | tee -a "$LOG"
python3 - "$OUT" <<'PYEOF' >> "$LOG" 2>&1 || true
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
names = z.namelist()
print(f"valid ZIP: {len(names)} entries")
print("AndroidManifest.xml:", "AndroidManifest.xml" in names)
print("classes.dex:", any(n.startswith("classes") and n.endswith(".dex") for n in names))
print("lib/ABIs:", sorted({n.split('/')[1] for n in names if n.startswith("lib/")}))
PYEOF
exit 0
