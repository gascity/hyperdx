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
| `main` | clean mirror of `upstream/main` — **never patched**, only for pulling/diffing |
| `gascity-sso` | our build branch: a release tag + our patch. **This is what we build/test/install.** |

`origin` = `gascity/hyperdx`, `upstream` = `hyperdxio/hyperdx`.

`gascity-sso` is based on the release tag matching our deployed version
(initially `@hyperdx/app@2.28.0`). Keeping it anchored to a **release tag** (not
`main`) means the only delta from a stock image is our patch — no surprise
version jump.

## Updating from upstream (rebase)

```bash
git fetch upstream --tags
# replay our patch onto a newer release we want to adopt:
git rebase --onto '@hyperdx/app@<NEW>' '@hyperdx/app@<CURRENT>' gascity-sso
# resolve (rare — the patch lives in stable, isolated code), then:
#   build the image from gascity-sso -> push to our registry -> repin the GitOps digest
```

Our changes are kept as a tight, well-isolated set so rebases are near-trivial.
A conflict is almost always a one-line re-placement of the hook in
`isUserAuthenticated`.

**CI guard (required):** the build must assert the patch symbols are present in
the produced image (e.g. grep the compiled output for `IS_PROXY_AUTH_ENABLED` /
`proxyHeaderAuth`). The one silent failure mode is forgetting to repin the
GitOps digest after a rebase and shipping stock upstream, which quietly
re-introduces the second login.

## The patch — proxy-header auth

Files (kept minimal to ease rebasing):

- **`packages/api/src/middleware/proxyHeaderAuth.ts`** *(new, 100% ours — never
  conflicts)* — reads the gate-asserted email, optional shared-secret check,
  email-domain allowlist, find-or-create the user, attach to the single team,
  `req.login()`.
- **`packages/api/src/middleware/auth.ts`** *(one hook)* — in `isUserAuthenticated`,
  after the existing `IS_LOCAL_APP_MODE` bypass, honor the gate identity. When
  proxy auth is disabled, `getProxyAuthEmail()` returns `null` and behavior is
  byte-for-byte stock.
- **`packages/api/src/config.ts`** *(additive)* — the `PROXY_AUTH_*` env config.

The second login disappears with **no frontend change**: the SPA only bounces to
`/login` when `/api/me` returns 401; once the gate-asserted session is
established, `/api/me` returns 200 and the bounce never fires.

### Configuration (env)

| env | default | meaning |
| --- | --- | --- |
| `PROXY_AUTH_ENABLED` | `false` | master switch; unset = stock HyperDX |
| `PROXY_AUTH_HEADER` | `x-auth-request-email` | header the gate sets to the SSO email |
| `PROXY_AUTH_ALLOWED_EMAIL_DOMAINS` | `` (deny-all) | comma-separated domains allowed to auto-provision |
| `PROXY_AUTH_SHARED_SECRET` | `` (off) | if set, the request must also carry the secret header |
| `PROXY_AUTH_SECRET_HEADER` | `x-hdx-proxy-auth-secret` | header carrying the shared secret |

Break-glass password login (`/login/password`) is intentionally left intact.

## ⚠️ Security model — the trust boundary is the EDGE

The patch trusts an HTTP header. That is only safe if the edge guarantees the
header can come **only** from the gate. The patch alone does **not** make it
safe. Deployments MUST:

1. **Strip client-supplied `PROXY_AUTH_HEADER` (and `PROXY_AUTH_SECRET_HEADER`)
   on inbound** at the gate, re-setting them only after a successful SSO.
   (HyperDX's Next.js proxy forwards inbound headers unchanged, and `trust proxy`
   makes any in-app IP check unreliable — so this strip is non-negotiable.)
2. **NetworkPolicy** so only the gate can reach the app port.
3. **Set `PROXY_AUTH_SHARED_SECRET`** (injected by the gate, never exposed to the
   browser) as an in-app backstop that survives an edge header-strip misconfig.
4. **Scope `PROXY_AUTH_ALLOWED_EMAIL_DOMAINS`** so the gate can't provision
   arbitrary identities.

Note: OSS HyperDX has **no RBAC** — every user lands in the one shared team with
identical permissions. *Who* is allowed in is an Authentik decision, not HyperDX.
