# gascity/hyperdx — downstream fork

This is Gas City's fork of [hyperdxio/hyperdx](https://github.com/hyperdxio/hyperdx).
We run HyperDX self-hosted as our logs/traces UI over our existing ClickHouse.

It carries **one** change on top of upstream: **reverse-proxy (forward-auth) SSO**,
so that authenticating once through our Authentik gate is the only login users see.
HyperDX OSS has no native SSO/OIDC (it's reserved for the commercial tier; the
upstream request for this, PR #1306, was closed un-merged), so we maintain it
ourselves as a thin, isolated patch.

## Branch model

| branch | purpose |
| --- | --- |
| `gascity-sso` | **default branch** and build branch: an upstream release tag + our patch. **This is what we build/test/install**, so Dependabot / code scanning track what is deployed. |
| `main` | frozen copy of an old upstream `main`; not built, not synced. Diff against the `upstream` remote instead. |

`origin` = `gascity/hyperdx`, `upstream` = `hyperdxio/hyperdx`.

`gascity-sso` is based on the release tag matching our deployed version
(currently `@hyperdx/app@2.42.0`; it was `@hyperdx/app@2.28.0` until 2026-10).
Keeping it anchored to a **release tag** (not `main`) means the only delta from
a stock image is our patch — no surprise version jump.

Only `gascity-image.yml` and `gascity-pr.yml` live in `.github/workflows` on this
branch. Upstream's workflows are deleted here (schedule, issue and
`pull_request_target` events read workflow files from the default branch, so
they would otherwise run on this public fork) and both of our workflows fail if
a rebase brings one back.

## Updating from upstream

`gascity-sso` is protected (required `auth quality gate` check from
`gascity-pr.yml`, no force-push, admins included), so an upgrade is a **new
patch stack on the new release tag, integrated by a normal PR**, never a rebase
of `gascity-sso` in place. Each generation's old tip is tagged
`gascity-sso/<version>` so the next upgrade can tell this generation's commits
from the previous ones (which stay reachable through the integration merge).

```bash
git fetch upstream --tags && git fetch origin --tags
CUR=2.42.0 NEW=<x.y.z>
# 1. replay this generation's fork commits onto the new release
git switch -c "gascity/rebase-$NEW" "@hyperdx/app@$NEW"
git cherry-pick $(git rev-list --reverse --no-merges "@hyperdx/app@$CUR..origin/gascity-sso" \
  --not $(git tag -l 'gascity-sso/*'))
# modify/delete conflicts on upstream workflow files: keep them deleted
git status --porcelain | awk '$1 ~ /D/ && $2 ~ /^\.github\/workflows\// {print $2}' | xargs -r git rm -q
# and delete any NEW upstream workflow file the release added
find .github/workflows -maxdepth 1 -type f ! -name 'gascity-*' -print0 | xargs -0 -r git rm -q
# 2. tag the generation being replaced; merge it with -s ours (tree == new stack)
git tag "gascity-sso/$CUR" origin/gascity-sso
git merge -s ours --no-edit origin/gascity-sso
git push origin "gascity/rebase-$NEW" "refs/tags/gascity-sso/$CUR"
# 3. open a PR into gascity-sso; merge it once `auth quality gate` is green
#    (the push to gascity-sso then runs gascity-image: verify, build, publish)
```

Review the fork delta, not the PR diff (which carries the whole upstream
release): `git diff "@hyperdx/app@$NEW" "gascity/rebase-$NEW"` and
`git range-diff "@hyperdx/app@$CUR..origin/gascity-sso" "@hyperdx/app@$NEW..gascity/rebase-$NEW^1"`.
Keep the `gascity-pr.yml` job name `auth quality gate`: branch protection
requires that exact check.

Before pushing, run what `gascity-pr.yml` runs (immutable install, API
lint, `tsc --noEmit`, the `proxyHeaderAuth|proxyAuth*|config` Jest suites, API
build + symbol guard), build the prod image locally, and run the smoke test
(see "Verifying a build"). **A textually clean rebase is not evidence of a
working patch:** the 2.28 → 2.42 rebase applied without a single conflict and
still broke three ways (`setTraceAttributes` was removed from `auth.ts`, the API
build output moved from `build/src/*.js` to `build/*.js`, and the API lint
warning budget dropped below what the patch's tests added).

Our changes are kept as a tight, well-isolated set so rebases stay small. The
upstream-file footprint is: two lines in `api-app.ts`, a four-line hook in
`isUserAuthenticated` (`auth.ts`), an additive block in `config.ts`, the logout
redirect in `routers/api/root.ts`, and the credential strip in
`routers/api/clickhouseProxy.ts`. Everything else is in files that only we own.

**CI guard (required):** the build asserts the patch symbols are present in the
exact compiled files of the produced image (`config.js`, `middleware/auth.js`,
`middleware/proxyHeaderAuth.js`, `api-app.js` under `/app/packages/api/build`).
The one silent failure mode is forgetting to repin the GitOps digest after a
rebase and shipping stock upstream, which quietly re-introduces the second login.

## The patch — proxy-header auth

Files (kept minimal to ease rebasing):

- **`packages/api/src/middleware/proxyHeaderAuth.ts`** *(new, 100% ours — never
  conflicts)* — consumes the shared secret off the request, checks it
  (constant-time, current or previous value), reads the gate-asserted email,
  applies the email-domain allowlist, finds or creates the user in the single
  team, and calls `req.login()`.
- **`packages/api/src/middleware/auth.ts`** *(one hook)* — in `isUserAuthenticated`,
  after the existing `IS_LOCAL_APP_MODE` bypass: in proxy mode, unless the
  session already belongs to the gate identity, establish it (or 401), then
  re-enter so the request continues on the **stock** authenticated path
  (upstream's trace context and query attribution apply unchanged). With proxy
  auth disabled the hook is skipped and behavior is byte-for-byte stock.
- **`packages/api/src/api-app.ts`** *(one middleware)* — `consumeProxyAuthSecret`
  runs before every other middleware, so the secret is never in `req.headers`
  when the request logger or the ClickHouse proxy copy them.
- **`packages/api/src/config.ts`** *(additive)* — the `PROXY_AUTH_*` env config.
- **`packages/api/src/routers/api/clickhouseProxy.ts`** *(two lines,
  upstreamable)* — never forward the browser's `cookie` / `authorization` to the
  connection host, which any user can point at an arbitrary URL.

The second login disappears with **no frontend change**: the SPA only bounces to
`/login` when `/api/me` returns 401; once the gate-asserted session is
established, `/api/me` returns 200 and the bounce never fires.

### Configuration (env)

| env | default | meaning |
| --- | --- | --- |
| `PROXY_AUTH_ENABLED` | `false` | master switch; unset = stock HyperDX |
| `PROXY_AUTH_HEADER` | `x-auth-request-email` | header the gate sets to the SSO email |
| `PROXY_AUTH_ALLOWED_EMAIL_DOMAINS` | `` (deny-all) | comma-separated domains allowed to auto-provision |
| `PROXY_AUTH_SHARED_SECRET` | `` | **required when enabled** — the app refuses to start without it; the request must carry it in the secret header |
| `PROXY_AUTH_SHARED_SECRET_PREVIOUS` | `` | optional prior value accepted only during an attended rotation; when set, it must differ from the required current value |
| `PROXY_AUTH_SECRET_HEADER` | `x-hdx-proxy-auth-secret` | header carrying the shared secret |
| `PROXY_AUTH_LOGOUT_URL` | `/oauth2/sign_out` | where `/api/logout` sends the user under proxy auth (the gate's sign-out) |

Break-glass password login (`/login/password`) is left intact in code, but note
it is only reachable *behind* the gate and the gate identity wins on the next
request — so the real break-glass is flipping `PROXY_AUTH_ENABLED` off.

## ⚠️ Security model — the trust boundary is the EDGE

The patch trusts an HTTP header. That is only safe if the edge guarantees the
header can come **only** from the gate. The patch alone does **not** make it
safe. Deployments MUST:

1. **Strip client-supplied `PROXY_AUTH_HEADER` (and `PROXY_AUTH_SECRET_HEADER`)
   on inbound** at the gate, re-setting them only after a successful SSO.
   (HyperDX's Next.js proxy forwards inbound headers unchanged, and `trust proxy`
   makes any in-app IP check unreliable — so this strip is non-negotiable.)
2. **NetworkPolicy** so only the gate can reach the app port. Wherever some
   path can reach the app without transiting the gate (another proxy hop, an
   in-cluster client, a private-network listener), the shared secret below is
   the only thing standing between that path and full impersonation, so treat
   it as a credential with the same care as a signing key.
3. **Set `PROXY_AUTH_SHARED_SECRET`** (injected by the gate, never exposed to the
   browser) as an in-app backstop that survives an edge header-strip misconfig.
   This is **enforced**: the API refuses to start with proxy auth on and no
   current secret set. The app rejects identical current and previous values.
   Both values are read only at process startup; changing a Secret does not
   update a running API process. Rotation is an attended sequence:

   - deploy/restart every API instance with `PROXY_AUTH_SHARED_SECRET` set to the
     new value and `PROXY_AUTH_SHARED_SECRET_PREVIOUS` set to the old value, then
     prove readiness and that both values are accepted;
   - converge every gate injector to the new value and prove each gate; then
   - clear `PROXY_AUTH_SHARED_SECRET_PREVIOUS`, deploy/restart every API instance,
     and prove the new value is accepted while the old value is rejected.

   A one-replica `Recreate` deployment has a bounded interruption at each API
   restart; the overlap prevents credential mismatch during gate convergence but
   does not make those restarts zero-downtime. The patch also refuses to honor a
   session alone in proxy mode — every request must carry a gate-vouched
   identity, so a stolen/long-lived cookie cannot outlive the gate's session.
4. **Keep the secret out of logs and telemetry.** The app takes it off the
   request before logging or proxying (see above), but every hop that sets or
   forwards it must also redact it from its own logs, and HyperDX's own
   telemetry must go to a collector you control: with `HYPERDX_API_KEY` set and
   no `OTEL_EXPORTER_OTLP_ENDPOINT`, the bundled OpenTelemetry SDK exports the
   API's logs, traces and metrics to HyperDX's hosted endpoint by default.
5. **Scope `PROXY_AUTH_ALLOWED_EMAIL_DOMAINS`** so the gate can't provision
   arbitrary identities, **and** bind the Authentik *application* to the right
   group/policy — that binding is the **primary admission control** (who is
   allowed in at all). The domain allowlist is only a coarse backstop.

### Residual access vectors (know these)

- **API access keys bypass the gate.** Every user (including auto-provisioned SSO
  users) gets an `accessKey` (returned by `/me`). The `/api/v2` and `/mcp` Bearer
  paths authenticate by that key and **do not transit the gate**, so they survive
  an Authentik revocation. **Offboarding must delete the HyperDX user (or rotate
  the key — Team Settings → API & Agents → Rotate, since 2.36)**, not just
  disable the Authentik account.
- **No RBAC.** OSS HyperDX has no roles — every user lands in the one shared team
  with identical permissions. *Who* is allowed in is an Authentik decision, not
  HyperDX. First-time provisioning is logged as a distinct `user_provision` event
  for audit.
- **Logout** clears the HyperDX session and bounces to `PROXY_AUTH_LOGOUT_URL`
  (the gate sign-out); a true IdP logout needs that URL to chain to Authentik's
  end-session endpoint.

## Verifying a build

`gascity/smoke/` holds the local smoke harness used for the 2.42 rebase. It runs
an image against FerretDB with fake secrets and checks, through the app port and
the API port: no headers / identity without secret / wrong secret (same and
different length) / empty secret all 401; a bare session cookie 401s; a
gate-vouched request gets a session as that user; another identity replaces the
session; a foreign email domain 403s; logout bounces to the gate; and the secret
never appears in container stdout, the OTLP export, or the request the
ClickHouse proxy sends to the connection host. It also covers fail-closed
startup and the current/previous rotation window.
