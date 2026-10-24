#!/usr/bin/env bash
# Local smoke test for a gascity/hyperdx image: proxy-auth trust boundary,
# secret hygiene (logs, ClickHouse proxy, OTel export), and FerretDB state.
#
#   smoke.sh infra-up                 # network + FerretDB (prod-pinned) + capture servers
#   smoke.sh run <image> <name>       # start HyperDX <image> as container <name> (fake secrets)
#   smoke.sh bootstrap <name>         # first-team registration (prod already has a team)
#   smoke.sh auth <name>              # positive/negative auth matrix + leak checks
#   smoke.sh seed <name>              # create a dashboard, saved search, webhook, alert
#   smoke.sh verify-seed <name>       # read the seeded state back
#   smoke.sh failclosed <image>       # PROXY_AUTH_ENABLED without a secret must not start
#   smoke.sh stop <name> | infra-down
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
  docker run -d --name "$name" --network $NET \
    --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
    -e HYPERDX_API_PORT=8000 -e HYPERDX_APP_PORT=8080 -e HYPERDX_LOG_LEVEL=info \
    -e USAGE_STATS_ENABLED=false \
    -e PROXY_AUTH_ENABLED=true -e PROXY_AUTH_ALLOWED_EMAIL_DOMAINS=gascity.com \
    -e PROXY_AUTH_HEADER=x-auth-request-email -e PROXY_AUTH_SHARED_SECRET=$SECRET \
    -e HYPERDX_APP_URL=http://$HOST -e FRONTEND_URL=http://$HOST:8080 \
    -e SERVER_URL=http://127.0.0.1:8000 \
    -e MONGO_URI=mongodb://hyperdx:pgpass@hdx-ferretdb:27017/hyperdx \
    -e HYPERDX_API_KEY=smoke-dummy-ingest-key \
    -e OTEL_EXPORTER_OTLP_ENDPOINT=http://hdx-echo-otlp:4318 \
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
A=alice@gascity.com

bootstrap() {
  set_urls
  local c
  c=$(code -X POST $APP/api/register/password -H 'content-type: application/json' \
    -d '{"email":"owner@gascity.com","password":"Sm0ke-Test-Passw0rd!","confirmPassword":"Sm0ke-Test-Passw0rd!"}')
  echo "register first team owner: $c"
}

auth() {
  TARGET=$1; set_urls
  local name=$1 base=$APP/api jar=$(mktemp) body
  rm -f $jar
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
  expect "T6 bare session cookie (no gate headers) -> 401" 401 "$(code -b $jar $base/me)"
  expect "T6b session cookie + wrong secret -> 401" 401 "$(gcode alice@gascity.com $WRONG_SAME_LEN -b $jar $base/me)"
  expect "T7 domain outside allowlist -> 403" 403 "$(gcode mallory@evil.com $SECRET $base/me)"
  expect "T8 multi-valued identity header -> 401" 401 "$(gcode 'a@gascity.com,b@gascity.com' $SECRET $base/me)"
  local c8; c8=$(gcode $'a\x01b@gascity.com' $SECRET $base/me)
  case $c8 in 400|401) ok "T8b control char in identity rejected (got $c8; 400 = Node's header parser)";;
    *) ko "T8b control char in identity (got $c8)";; esac
  body=$(gcurl bob@gascity.com $SECRET -b $jar $base/me)
  expect "T9 alice's cookie + gate says bob -> /me is bob" bob@gascity.com \
    "$(echo "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("email"))' 2>/dev/null || echo none)"
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
  # with the SSO gate's cookie, as a browser behind oauth2-proxy would send it
  gcurl alice@gascity.com $SECRET -o /dev/null -X POST \
    -H 'cookie: _oauth2_proxy=FAKE-GATE-SESSION-COOKIE' \
    -H "x-hyperdx-connection-id: $cid" -H 'content-type: text/plain' \
    --data 'SELECT 1 FORMAT JSON' "$base/clickhouse-proxy?query=SELECT%201" || true
  sleep 1
  echo "INFO CH proxy captured $(wc -l < $CAP/ch.jsonl) request(s) at the connection host"
  if grep -q "$SECRET" $CAP/ch.jsonl; then ko "T13 shared secret forwarded to the connection host"
  else ok "T13 shared secret not forwarded to the connection host"; fi
  if grep -q 'FAKE-GATE-SESSION-COOKIE' $CAP/ch.jsonl; then ko "T13b SSO gate cookie forwarded to the connection host"
  else ok "T13b SSO gate cookie not forwarded to the connection host"; fi
  # Request logs (stdout -> pod logs -> otel_logs in prod)
  sleep 2
  docker logs "$name" > $CAP/stdout.$name.log 2>&1 || true
  local nl; nl=$(grep -c "$SECRET" $CAP/stdout.$name.log || true)
  if [ "$nl" -gt 0 ]; then ko "T14 shared secret written to container stdout ($nl lines)"
  else ok "T14 shared secret absent from container stdout"; fi
  nl=$(grep -c 'connect.sid=' $CAP/stdout.$name.log || true)
  if [ "$nl" -gt 0 ]; then ko "T14b session cookie written to container stdout ($nl lines)"
  else ok "T14b session cookie absent from container stdout"; fi
  sleep 8  # let the OTLP batch processors flush
  if grep -q "$SECRET" $CAP/otlp.jsonl 2>/dev/null; then
    ko "T15 shared secret exported via OTLP ($(grep -c "$SECRET" $CAP/otlp.jsonl) export requests)"
  else ok "T15 shared secret absent from OTLP export"; fi
  echo "INFO OTLP export requests captured so far: $(wc -l < $CAP/otlp.jsonl 2>/dev/null || echo 0)"
  echo "SUMMARY $name: $pass passed, $fail failed"
  rm -f $jar $jar.pw
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

failclosed() {
  local img=$1 out
  out=$(docker run --rm --network $NET --user 1000:1000 \
    -e PROXY_AUTH_ENABLED=true -e MONGO_URI=mongodb://hyperdx:pgpass@hdx-ferretdb:27017/hyperdx \
    -e FRONTEND_URL=http://localhost:8080 "$img" 2>&1 | head -c 20000 || true)
  if echo "$out" | grep -q 'requires PROXY_AUTH_SHARED_SECRET'; then
    ok "T16 refuses to start with PROXY_AUTH_ENABLED and no secret"
  else ko "T16 started (or failed differently) without a secret"; fi
}

case "${1:-}" in
  infra-up) infra_up ;;
  infra-down) docker rm -f hdx-pg hdx-ferretdb hdx-echo-ch hdx-echo-otlp >/dev/null 2>&1 || true
              docker network rm $NET >/dev/null 2>&1 || true ;;
  run) shift; run "$@" ;;
  stop) docker rm -f "$2" >/dev/null ;;
  bootstrap) TARGET=$2; bootstrap ;;
  auth) auth "$2" ;;
  seed) TARGET=$2; seed ;;
  verify-seed) TARGET=$2; verify_seed ;;
  failclosed) failclosed "$2" ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
