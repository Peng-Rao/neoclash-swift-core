#!/usr/bin/env bash
#
# Smoke-test reachability of popular sites through a running NeoClash mixed proxy.
#
# Start the core first, e.g.:
#   swift run NeoClashSwiftCore -f config.yaml -d /tmp/neoclash-rt
# then:
#   scripts/smoke-sites.sh [proxy-host:port] [controller-host:port]
#
# A site counts as reachable if the proxy returns any HTTP response (2xx/3xx/4xx).
# A connection failure shows as HTTP 000 -> FAIL. 3xx/4xx are the sites' own
# responses (redirects, auth walls, CDN root 403) and still mean the proxy reached them.

set -u

PROXY="${1:-127.0.0.1:7897}"
CONTROLLER="${2:-127.0.0.1:9090}"
TIMEOUT="${TIMEOUT:-25}"

trace=$(curl -x "http://$PROXY" -s -m "$TIMEOUT" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)
echo "proxy=$PROXY  controller=$CONTROLLER"
echo "exit: $(printf '%s' "$trace" | grep -E '^ip=|^loc=' | tr '\n' ' ')"
echo

SITES=(
  "Google|https://www.google.com"
  "Google Search|https://www.google.com/search?q=hello"
  "YouTube|https://www.youtube.com"
  "Gmail|https://mail.google.com"
  "Telegram|https://telegram.org"
  "Telegram API|https://api.telegram.org"
  "Telegram Core|https://core.telegram.org"
  "Telegram Web|https://web.telegram.org"
  "Discord|https://discord.com"
  "Discord Gateway|https://discord.com/api/v9/gateway"
  "Discord CDN|https://cdn.discordapp.com"
  "X (Twitter)|https://x.com"
  "GitHub|https://github.com"
  "Wikipedia|https://www.wikipedia.org"
  "OpenAI API|https://api.openai.com"
)

pass=0
fail=0
printf "%-22s %-6s %-9s %-10s %s\n" "SITE" "HTTP" "TIME(s)" "BYTES" "RESULT"
for entry in "${SITES[@]}"; do
  name="${entry%%|*}"
  url="${entry#*|}"
  read -r code time size < <(curl -x "http://$PROXY" -s -m "$TIMEOUT" -o /dev/null \
    -w "%{http_code} %{time_total} %{size_download}" "$url" 2>/dev/null || echo "000 0 0")
  if [ "${code:-000}" != "000" ]; then
    result="PASS"
    pass=$((pass + 1))
  else
    result="FAIL"
    fail=$((fail + 1))
  fi
  printf "%-22s %-6s %-9s %-10s %s\n" "$name" "${code:-000}" "${time:-0}" "${size:-0}" "$result"
done

echo
echo "reachable: $pass / $((pass + fail))"
[ "$fail" -eq 0 ]
