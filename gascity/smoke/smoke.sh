#!/usr/bin/env bash
# Local smoke test for a gascity/hyperdx image: proxy-auth trust boundary,
# secret hygiene (logs, ClickHouse proxy, OTel export), and FerretDB state.
#
#   smoke.sh infra-up                 # network + FerretDB (prod-pinned) + capture servers
#   smoke.sh run <image> <name>       # start HyperDX <image> as container <name> (fake secrets)
#   smoke.sh bootstrap <name>         # first-team registration (prod already has a team)
#   smoke.sh auth <name>              # positive/negative auth matrix + leak checks
#   smoke.sh telemetry <name>         # SMOKE_TELEMETRY=off run: self-telemetry stays off
#   smoke.sh seed <name>              # create a dashboard, saved search, webhook, alert
#   smoke.sh verify-seed <name>       # read the seeded state back
#   smoke.sh failclosed <image>       # unsafe proxy-auth configs must not start
#   smoke.sh rotation <image>         # current/previous secret overlap window
#   smoke.sh stop <name> | infra-down
#
# `run` knobs: SMOKE_LOG_LEVEL (default info; use trace for the most verbose
# request logs), SMOKE_TELEMETRY=off (no HYPERDX_API_KEY and no OTLP endpoint,
# the production posture), SMOKE_SECRET / SMOKE_SECRET_PREVIOUS (rotation).
set -euo pipefail

NET=hdx-smoke
PG_IMG=ghcr.io/ferretdb/postgres-documentdb@sha256:4a2364db8c91fd82855a4eab326202e247aa9ed6a6e8a85c76c1693a5a9ab408
FDB_IMG=ghcr.io/ferretdb/ferretdb@sha256:7449f6ce1e75b187c328c9ce65ec4e8963767b34b4d604f9b9b6605c6d8d3ee7
HERE=$(cd "$(dirname "$0")" && pwd)
CAP=${CAP:-/tmp/hdx-smoke-captures}
# Fake, test-only values. Same length for the wrong secret so the
# timingSafeEqual branch (not the length short-circuit) is exercised too.
SECRET=smoke-secret-0123456789abcdef0123456789abcdef
WRONG_SAME_LEN=smoke-secret-ffffffffffffffffffffffffffffffff
NEW_SECRET=smoke-rotated-secret-fedcba9876543210fedcba98
# Browser credentials that must never reach stdout or the connection host.
GATE_COOKIE=FAKE-GATE-SESSION-COOKIE
BEARER=FAKE-BEARER-ACCESS-KEY-0123456789
# No host port publishing (shared host, contested ports): talk to the
# container's bridge IP directly. TARGET is the HyperDX container name.
TARGET=${TARGET:-hdx-target}
cip() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1"; }
HOST=hdx.smoke.test
APP="http://$HOST:8080"; API="http://$HOST:8000"; IP=127.0.0.1
set_urls() { IP=$(cip "$TARGET"); }
pass=0; fail=0
ok() { echo "PASS $*"; pass=$((pass + 1)); }
ko() { echo "FAIL $*"; fail=$((fail + 1)); }
expect() { # expect <desc> <want> <got>
  if [ "$2" = "$3" ]; then ok "$1 (got $3)"; else ko "$1 (want $2, got $3)"; fi
}
curl() { command curl --resolve "$HOST:8080:$IP" --resolve "$HOST:8000:$IP" "$@"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

infra_up() {
  docker network inspect $NET >/dev/null 2>&1 || docker network create $NET >/dev/null
  mkdir -p $CAP && chmod 0777 $CAP
  docker run -d --name hdx-pg --network $NET \
    -e POSTGRES_USER=hyperdx -e POSTGRES_PASSWORD=pgpass -e POSTGRES_DB=postgres \
    -e PGDATA=/var/lib/postgresql/data/pgdata $PG_IMG >/dev/null
  for _ in $(seq 1 60); do
    docker exec hdx-pg pg_isready -U hyperdx -d postgres >/dev/null 2>&1 && break; sleep 2
  done
  docker run -d --name hdx-ferretdb --network $NET \
    -e FERRETDB_POSTGRESQL_URL=postgres://hyperdx:pgpass@hdx-pg:5432/postgres $FDB_IMG >/dev/null
  # capture servers: a fake ClickHouse (connection host) and a fake OTLP endpoint
  docker run -d --name hdx-echo-ch --network $NET --user "$(id -u):$(id -g)" -v "$HERE":/srv:ro \
    -v $CAP:/captures python:3.12-alpine sh -c \
    'cp /srv/echo.py /tmp/e.py && sed -i s#requests.jsonl#ch.jsonl# /tmp/e.py && python /tmp/e.py 8123' >/dev/null
  docker run -d --name hdx-echo-otlp --network $NET --user "$(id -u):$(id -g)" -v "$HERE":/srv:ro \
    -v $CAP:/captures python:3.12-alpine sh -c \
    'cp /srv/echo.py /tmp/e.py && sed -i s#requests.jsonl#otlp.jsonl# /tmp/e.py && python /tmp/e.py 4318' >/dev/null
  sleep 3
}

run() { # run <image> <name> [extra docker args...]
  local img=$1 name=$2; shift 2
  local telemetry=(-e HYPERDX_API_KEY=smoke-dummy-ingest-key
    -e OTEL_EXPORTER_OTLP_ENDPOINT=http://hdx-echo-otlp:4318)
  [ "${SMOKE_TELEMETRY:-capture}" = off ] && telemetry=()
  local previous=()
  [ -n "${SMOKE_SECRET_PREVIOUS:-}" ] &&
    previous=(-e "PROXY_AUTH_SHARED_SECRET_PREVIOUS=$SMOKE_SECRET_PREVIOUS")
  docker run -d --name "$name" --network $NET \
    --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
    -e HYPERDX_API_PORT=8000 -e HYPERDX_APP_PORT=8080 \
    -e "HYPERDX_LOG_LEVEL=${SMOKE_LOG_LEVEL:-info}" \
    -e USAGE_STATS_ENABLED=false \
    -e PROXY_AUTH_ENABLED=true -e PROXY_AUTH_ALLOWED_EMAIL_DOMAINS=gascity.com \
    -e PROXY_AUTH_HEADER=x-auth-request-email \
    -e "PROXY_AUTH_SHARED_SECRET=${SMOKE_SECRET:-$SECRET}" "${previous[@]}" \
    -e HYPERDX_APP_URL=http://$HOST -e FRONTEND_URL=http://$HOST:8080 \
    -e SERVER_URL=http://127.0.0.1:8000 \
    -e MONGO_URI=mongodb://hyperdx:pgpass@hdx-ferretdb:27017/hyperdx \
    "${telemetry[@]}" \
    -e 'DEFAULT_CONNECTIONS=[{"name":"Smoke ClickHouse","host":"http://hdx-echo-ch:8123","username":"ro","password":"ro-pass"}]' \
    -e 'DEFAULT_SOURCES=[{"from":{"databaseName":"otel","tableName":"otel_logs"},"kind":"log","name":"Logs","timestampValueExpression":"Timestamp","displayedTimestampValueExpression":"Timestamp","implicitColumnExpression":"Body","serviceNameExpression":"ServiceName","bodyExpression":"Body","eventAttributesExpression":"LogAttributes","resourceAttributesExpression":"ResourceAttributes","defaultTableSelectExpression":"Timestamp,ServiceName,SeverityText,Body","severityTextExpression":"SeverityText","traceIdExpression":"TraceId","spanIdExpression":"SpanId","connection":"Smoke ClickHouse"}]' \
    "$@" "$img" >/dev/null
  TARGET=$name; set_urls
  for _ in $(seq 1 90); do
    [ "$(code $API/health)" = 200 ] && [ "$(code $APP/)" != 000 ] && break
    sleep 2
  done
  sleep 3
  echo "started $name ($img) at $APP: api /health=$(code $API/health)"
}

# gcurl <email> <secret> <curl args...>: a request as the gate would forward it
gcurl() { local e=$1 s=$2; shift 2; curl -s -H "x-auth-request-email: $e" -H "x-hdx-proxy-auth-secret: $s" "$@"; }
gcode() { local e=$1 s=$2; shift 2; gcurl "$e" "$s" -o /dev/null -w '%{http_code}' "$@"; }

bootstrap() {
  set_urls
  local c
  c=$(code -X POST $APP/api/register/password -H 'content-type: application/json' \
    -d '{"email":"owner@gascity.com","password":"Sm0ke-Test-Passw0rd!","confirmPassword":"Sm0ke-Test-Passw0rd!"}')
  echo "register first team owner: $c"
}

auth() {
  TARGET=$1; set_urls
  local name=$1 base=$APP/api jar body
  jar=$(mktemp); rm -f $jar
  : > $CAP/ch.jsonl; : > $CAP/otlp.jsonl
  expect "T1 no headers -> 401" 401 "$(code $base/me)"
  expect "T2 identity header without secret -> 401" 401 \
    "$(code -H 'x-auth-request-email: alice@gascity.com' $base/me)"
  expect "T3 wrong secret (same length) -> 401" 401 "$(gcode alice@gascity.com $WRONG_SAME_LEN $base/me)"
  expect "T4 wrong secret (other length) -> 401" 401 "$(gcode alice@gascity.com short $base/me)"
  expect "T4b empty secret header -> 401" 401 \
    "$(code -H 'x-auth-request-email: alice@gascity.com' -H 'x-hdx-proxy-auth-secret;' $base/me)"
  body=$(gcurl Alice@GasCity.com $SECRET -c $jar $base/me)
  expect "T5 gate identity + secret -> /me is alice" alice@gascity.com \
    "$(echo "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("email"))' 2>/dev/null || echo none)"
  # header names as the edge proxy sends them (canonical case); T14 then
  # checks that this spelling is consumed before logging as well
  body=$(curl -s -H 'X-Auth-Request-Email: alice@gascity.com' -H "X-Hdx-Proxy-Auth-Secret: $SECRET" $base/me)
  expect "T5b canonical-case gate headers -> /me is alice" alice@gascity.com \
    "$(echo "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("email"))' 2>/dev/null || echo none)"
  expect "T5c trailing-dot domain -> 401" 401 "$(gcode alice@gascity.com. $SECRET $base/me)"
  body=$(gcurl alice+x@gascity.com $SECRET $base/me)
  expect "T5d plus-address is its own identity, never linked to alice" alice+x@gascity.com \
    "$(echo "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("email"))' 2>/dev/null || echo none)"
  expect "T6 bare session cookie (no gate headers) -> 401" 401 "$(code -b $jar $base/me)"
  expect "T6b session cookie + wrong secret -> 401" 401 "$(gcode alice@gascity.com $WRONG_SAME_LEN -b $jar $base/me)"
  expect "T7 domain outside allowlist -> 403" 403 "$(gcode mallory@evil.com $SECRET $base/me)"
  expect "T8 multi-valued identity header -> 401" 401 "$(gcode 'a@gascity.com,b@gascity.com' $SECRET $base/me)"
  local c8; c8=$(gcode $'a\x01b@gascity.com' $SECRET $base/me)
  case $c8 in 400|401) ok "T8b control char in identity rejected (got $c8; 400 = Node's header parser)";;
    *) ko "T8b control char in identity (got $c8)";; esac
  local sid_alice sid_bob
  sid_alice=$(awk '$6 == "connect.sid" {print $7}' $jar)
  body=$(gcurl bob@gascity.com $SECRET -b $jar -c $jar.bob $base/me)
  expect "T9 alice's cookie + gate says bob -> /me is bob" bob@gascity.com \
    "$(echo "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("email"))' 2>/dev/null || echo none)"
  sid_bob=$(awk '$6 == "connect.sid" {print $7}' $jar.bob)
  if [ -n "$sid_alice" ] && [ -n "$sid_bob" ] && [ "$sid_alice" != "$sid_bob" ]; then
    ok "T9b identity switch issues a new session id (no fixation)"
  else ko "T9b identity switch kept the session id (alice=${sid_alice:0:12} bob=${sid_bob:0:12})"; fi
  expect "T10 password login does not bypass the gate" 401 "$(
    curl -s -o /dev/null -c $jar.pw -X POST -H 'content-type: application/json' \
      -d '{"email":"owner@gascity.com","password":"Sm0ke-Test-Passw0rd!"}' $base/login/password
    code -b $jar.pw $base/me)"
  expect "T11 direct API port (8000) enforces the same gate" 401 \
    "$(code -H 'x-auth-request-email: alice@gascity.com' $API/me)"
  expect "T11b direct API port with gate identity" 200 "$(gcode alice@gascity.com $SECRET $API/me)"
  local loc
  loc=$(gcurl alice@gascity.com $SECRET -o /dev/null -w '%{redirect_url}' $base/logout)
  expect "T12 logout bounces to the gate sign-out" /oauth2/sign_out "${loc#$APP}"
  # ClickHouse proxy: what reaches the (user-configurable) connection host?
  local cid
  cid=$(gcurl alice@gascity.com $SECRET -b $jar $base/connections | python3 -c \
    'import json,sys; d=json.load(sys.stdin); d=d.get("data",d) if isinstance(d,dict) else d; print(d[0].get("id") or d[0].get("_id"))')
  # with the SSO gate's cookie and a bearer token, as a browser behind
  # oauth2-proxy (or a script holding an access key) could send them
  gcurl alice@gascity.com $SECRET -o /dev/null -X POST \
    -H "cookie: _oauth2_proxy=$GATE_COOKIE" -H "authorization: Bearer $BEARER" \
    -H "x-hyperdx-connection-id: $cid" -H 'content-type: text/plain' \
    --data 'SELECT 1 FORMAT JSON' "$base/clickhouse-proxy?query=SELECT%201" || true
  sleep 1
  echo "INFO CH proxy captured $(wc -l < $CAP/ch.jsonl) request(s) at the connection host"
  if grep -q "$SECRET" $CAP/ch.jsonl; then ko "T13 shared secret forwarded to the connection host"
  else ok "T13 shared secret not forwarded to the connection host"; fi
  if grep -q "$GATE_COOKIE" $CAP/ch.jsonl; then ko "T13b SSO gate cookie forwarded to the connection host"
  else ok "T13b SSO gate cookie not forwarded to the connection host"; fi
  if grep -q "$BEARER" $CAP/ch.jsonl; then ko "T13c bearer token forwarded to the connection host"
  else ok "T13c bearer token not forwarded to the connection host"; fi
  # error paths must not log the secret either (T14 scans their output)
  expect "T14e malformed JSON body (error handler path) -> 400" 400 \
    "$(gcode alice@gascity.com $SECRET -b $jar -X POST -H 'content-type: application/json' \
      --data '{"name":' $base/dashboards)"
  expect "T14f connection-test failure (console.error path) -> 500" 500 \
    "$(gcode alice@gascity.com $SECRET -b $jar -X POST -H 'content-type: application/json' \
      --data '{"host":"http://hdx-smoke-no-such-host.invalid:8123"}' $base/clickhouse-proxy/test)"
  # Request logs (stdout -> pod logs -> otel_logs in prod)
  sleep 2
  docker logs "$name" > $CAP/stdout.$name.log 2>&1 || true
  local nl; nl=$(grep -c "$SECRET" $CAP/stdout.$name.log || true)
  if [ "$nl" -gt 0 ]; then ko "T14 shared secret written to container stdout ($nl lines)"
  else ok "T14 shared secret absent from container stdout"; fi
  nl=$(grep -c 'connect.sid=' $CAP/stdout.$name.log || true)
  if [ "$nl" -gt 0 ]; then ko "T14b session cookie written to container stdout ($nl lines)"
  else ok "T14b session cookie absent from container stdout"; fi
  nl=$(grep -c "$GATE_COOKIE" $CAP/stdout.$name.log || true)
  if [ "$nl" -gt 0 ]; then ko "T14c SSO gate cookie written to container stdout ($nl lines)"
  else ok "T14c SSO gate cookie absent from container stdout"; fi
  nl=$(grep -c "$BEARER" $CAP/stdout.$name.log || true)
  if [ "$nl" -gt 0 ]; then ko "T14d bearer token written to container stdout ($nl lines)"
  else ok "T14d bearer token absent from container stdout"; fi
  echo "INFO container stdout: $(wc -l < $CAP/stdout.$name.log) lines," \
    "$(grep -c '"req":{' $CAP/stdout.$name.log || true) request-log lines"
  sleep 8  # let the OTLP batch processors flush
  if grep -q "$SECRET" $CAP/otlp.jsonl 2>/dev/null; then
    ko "T15 shared secret exported via OTLP ($(grep -c "$SECRET" $CAP/otlp.jsonl) export requests)"
  else ok "T15 shared secret absent from OTLP export"; fi
  if grep -q -e "$GATE_COOKIE" -e "$BEARER" -e 'connect.sid=' $CAP/otlp.jsonl 2>/dev/null; then
    ko "T15b browser credential (gate cookie, bearer or session cookie) exported via OTLP"
  else ok "T15b browser credentials absent from OTLP export"; fi
  echo "INFO OTLP export requests captured so far: $(wc -l < $CAP/otlp.jsonl 2>/dev/null || echo 0)"
  echo "SUMMARY $name: $pass passed, $fail failed"
  rm -f $jar $jar.pw $jar.bob
}

# Production posture (SMOKE_TELEMETRY=off at `run`): no HYPERDX_API_KEY and no
# OTLP endpoint, so neither the API, the alert task nor the browser starts the
# bundled OpenTelemetry SDK (the Next standalone server ships no
# instrumentation hook at all).
telemetry() {
  TARGET=$1; set_urls
  local name=$1 body nl
  : > $CAP/otlp.jsonl
  gcurl alice@gascity.com $SECRET -o /dev/null $APP/api/me
  body=$(curl -s $APP/api/config)
  expect "TEL1 /api/config hands out no apiKey" absent \
    "$(echo "$body" | python3 -c 'import json,sys; print("present" if json.load(sys.stdin).get("apiKey") else "absent")' 2>/dev/null || echo unparsable)"
  sleep 8
  docker logs "$name" > $CAP/stdout.$name.log 2>&1 || true
  nl=$(grep 'OpenTelemetry SDK initialization skipped' $CAP/stdout.$name.log |
    sed -n 's/^\[\([A-Z-]*\)\].*/\1/p' | sort -u | tr '\n' ' ' || true)
  expect "TEL2 SDK initialization skipped in the API and the alert task" "ALERT-TASK API " "$nl"
  nl=$(grep -c -i 'health check \(passed\|failed\)' $CAP/stdout.$name.log || true)
  expect "TEL3 no SDK health checks against an export endpoint" 0 "$nl"
  expect "TEL4 nothing exported over OTLP" 0 "$(wc -l < $CAP/otlp.jsonl)"
  echo "SUMMARY $name telemetry: $pass passed, $fail failed"
}

# Rotation window (attended): current=new + previous=old accepts both, then
# clearing previous rejects the old value. previous == current must refuse to
# start without printing the value.
rotation() {
  local img=$1 out
  SMOKE_SECRET=$NEW_SECRET SMOKE_SECRET_PREVIOUS=$SECRET run "$img" hdx-rot
  expect "R1 previous (old) secret accepted during overlap" 200 "$(gcode alice@gascity.com $SECRET $API/me)"
  expect "R2 current (new) secret accepted during overlap" 200 "$(gcode alice@gascity.com $NEW_SECRET $API/me)"
  expect "R3 any other secret rejected during overlap" 401 "$(gcode alice@gascity.com $WRONG_SAME_LEN $API/me)"
  docker rm -f hdx-rot >/dev/null
  SMOKE_SECRET=$NEW_SECRET run "$img" hdx-rot
  expect "R4 old secret rejected once previous is cleared" 401 "$(gcode alice@gascity.com $SECRET $API/me)"
  expect "R5 new secret accepted once previous is cleared" 200 "$(gcode alice@gascity.com $NEW_SECRET $API/me)"
  docker rm -f hdx-rot >/dev/null
  out=$(start_refused "$img" -e PROXY_AUTH_ENABLED=true \
    -e "PROXY_AUTH_SHARED_SECRET=$NEW_SECRET" -e "PROXY_AUTH_SHARED_SECRET_PREVIOUS=$NEW_SECRET")
  if echo "$out" | grep -q 'PROXY_AUTH_SHARED_SECRET_PREVIOUS must differ'; then
    ok "R6 previous == current refuses to start"
  else ko "R6 previous == current started (or failed differently)"; fi
  if echo "$out" | grep -q "$NEW_SECRET"; then ko "R6b the refusal printed the secret"
  else ok "R6b the refusal does not print the secret"; fi
  echo "SUMMARY rotation: $pass passed, $fail failed"
}

seed() {
  set_urls
  local base=$APP/api src wh ss
  src=$(gcurl alice@gascity.com $SECRET $base/sources | python3 -c \
    'import json,sys; d=json.load(sys.stdin); print(d[0].get("id") or d[0].get("_id"))')
  gcurl alice@gascity.com $SECRET -o /dev/null -w 'dashboard %{http_code}\n' -X POST \
    -H 'content-type: application/json' $base/dashboards \
    -d '{"name":"smoke-dashboard","tiles":[],"tags":["smoke"]}'
  ss=$(gcurl alice@gascity.com $SECRET -X POST -H 'content-type: application/json' $base/saved-search \
    -d "{\"name\":\"smoke-search\",\"select\":\"\",\"where\":\"SeverityText:error\",\"whereLanguage\":\"lucene\",\"source\":\"$src\",\"tags\":[]}" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("id") or d.get("_id"))')
  echo "saved search $ss"
  wh=$(gcurl alice@gascity.com $SECRET -X POST -H 'content-type: application/json' $base/webhooks \
    -d '{"name":"smoke-hook","service":"generic","url":"https://example.com/hook","body":"{}"}' \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); d=d.get("data",d); print(d.get("id") or d.get("_id"))')
  echo "webhook $wh"
  gcurl alice@gascity.com $SECRET -o /dev/null -w 'alert %{http_code}\n' -X POST \
    -H 'content-type: application/json' $base/alerts \
    -d "{\"source\":\"saved_search\",\"savedSearchId\":\"$ss\",\"interval\":\"5m\",\"threshold\":1,\"thresholdType\":\"above\",\"channel\":{\"type\":\"webhook\",\"webhookId\":\"$wh\"}}"
}

verify_seed() {
  set_urls
  local base=$APP/api
  echo "dashboards: $(gcurl alice@gascity.com $SECRET $base/dashboards | python3 -c 'import json,sys; d=json.load(sys.stdin); d=d.get("data",d) if isinstance(d,dict) else d; print([x.get("name") for x in d])')"
  echo "saved searches: $(gcurl alice@gascity.com $SECRET $base/saved-search | python3 -c 'import json,sys; d=json.load(sys.stdin); d=d.get("data",d) if isinstance(d,dict) else d; print([x.get("name") for x in d])')"
  echo "alerts: $(gcurl alice@gascity.com $SECRET $base/alerts | python3 -c 'import json,sys; d=json.load(sys.stdin); d=d.get("data",d) if isinstance(d,dict) else d; print([(x.get("displayName"), x.get("tags"), x.get("state")) for x in d])')"
  echo "me: $(gcurl alice@gascity.com $SECRET $base/me | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("email"), "accessKey" in d)')"
}

# start_refused <image> [docker args...]: run a config that must refuse to
# start; print up to 20 kB of its output. Waits at most 90 s, then removes the
# container either way, so an image that wrongly starts is not left running.
start_refused() {
  local img=$1; shift
  docker rm -f hdx-refuse >/dev/null 2>&1 || true
  docker run -d --name hdx-refuse --network $NET --user 1000:1000 \
    -e MONGO_URI=mongodb://hyperdx:pgpass@hdx-ferretdb:27017/hyperdx \
    -e FRONTEND_URL=http://localhost:8080 "$@" "$img" >/dev/null
  timeout 90 docker wait hdx-refuse >/dev/null 2>&1 || true
  docker logs hdx-refuse 2>&1 | head -c 20000 || true
  docker rm -f hdx-refuse >/dev/null 2>&1 || true
}

failclosed() {
  local img=$1 out
  out=$(start_refused "$img" -e PROXY_AUTH_ENABLED=true)
  if echo "$out" | grep -q 'requires PROXY_AUTH_SHARED_SECRET'; then
    ok "T16 refuses to start with PROXY_AUTH_ENABLED and no secret"
  else ko "T16 started (or failed differently) without a secret"; fi
  # the SDK's advanced network capture records request headers (the secret
  # included) before the app can consume them
  out=$(start_refused "$img" -e PROXY_AUTH_ENABLED=true \
    -e "PROXY_AUTH_SHARED_SECRET=$SECRET" -e HDX_NODE_ADVANCED_NETWORK_CAPTURE=true)
  if echo "$out" | grep -q 'incompatible with HDX_NODE_ADVANCED_NETWORK_CAPTURE'; then
    ok "T16b refuses to start with advanced network capture on"
  else ko "T16b started (or failed differently) with advanced network capture on"; fi
  if echo "$out" | grep -q "$SECRET"; then ko "T16c the capture refusal printed the secret"
  else ok "T16c the capture refusal does not print the secret"; fi
}

case "${1:-}" in
  infra-up) infra_up ;;
  infra-down) docker rm -f hdx-pg hdx-ferretdb hdx-echo-ch hdx-echo-otlp >/dev/null 2>&1 || true
              docker network rm $NET >/dev/null 2>&1 || true ;;
  run) shift; run "$@" ;;
  stop) docker rm -f "$2" >/dev/null ;;
  bootstrap) TARGET=$2; bootstrap ;;
  auth) auth "$2" ;;
  telemetry) telemetry "$2" ;;
  seed) TARGET=$2; seed ;;
  verify-seed) TARGET=$2; verify_seed ;;
  failclosed) failclosed "$2" ;;
  rotation) rotation "$2" ;;
  *) sed -n '2,19p' "$0"; exit 2 ;;
esac
