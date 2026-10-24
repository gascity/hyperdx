// gascity fork — reverse-proxy (forward-auth) SSO. See GASCITY-FORK.md.
//
// Honors an identity asserted by a trusted upstream gate (oauth2-proxy in front
// of Authentik) so that SSO is the only login: when the gate forwards the
// authenticated user's email, we find-or-create the matching HyperDX user and
// establish a normal session. HyperDX OSS has no native SSO, so this is the
// minimal seam that reuses the gate we already run.
//
// SECURITY — the trust boundary is the EDGE, not this file:
//   1. the gate MUST strip any client-supplied identity/secret headers on
//      inbound and re-set them only after a successful SSO; and
//   2. a NetworkPolicy MUST ensure only the gate can reach this port.
// The current and optional previous proxy secrets are a strong in-app backstop
// (values the browser never sees, so they survive an edge header-strip
// misconfig). The email-domain allowlist is defense-in-depth, never the primary
// control.
import crypto from 'crypto';
import type { NextFunction, Request, Response } from 'express';

import * as config from '@/config';
import { findUserByEmail } from '@/controllers/user';
import Team from '@/models/team';
import User, { type UserDocument } from '@/models/user';
import logger from '@/utils/logger';

// RFC 5321 path limit; also bounds the work done on a header value.
const MAX_EMAIL_LENGTH = 254;
const WHITESPACE_OR_COMMA_RE = /[\s,]/;

// Rejects obviously malformed values (a comma => a multi-valued header) before a
// DB lookup. This is hygiene, NOT the security control -- the gate asserts the
// authoritative, already-authenticated address. Accepts exactly one '@', a
// non-empty local part, and a domain of two or more non-empty dot-separated
// labels, with no whitespace or comma anywhere. Checked structurally rather
// than with one backtracking regex, so a crafted header value costs linear time.
function isWellFormedEmail(s: string): boolean {
  if (s.length > MAX_EMAIL_LENGTH || WHITESPACE_OR_COMMA_RE.test(s)) {
    return false;
  }
  const at = s.indexOf('@');
  if (at <= 0 || s.includes('@', at + 1)) return false;
  const labels = s.slice(at + 1).split('.');
  return labels.length >= 2 && labels.every(label => label.length > 0);
}

// Control chars (\x00-\x1f, \x7f) aren't all matched by \s, and a ghost user
// differing from a real one only by an invisible byte is a real vector. Checked
// in code (not the regex) to avoid a no-control-regex lint carve-out.
function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

// The shared secret is injected by the gate on EVERY request, and two stock
// HyperDX paths copy req.headers verbatim: the pino-http request log (written to
// stdout and shipped to the log store) and the ClickHouse proxy (forwarded to
// the connection's host, which any HyperDX user can point anywhere). So the
// secret is taken off the request before any of that runs: consumeProxyAuthSecret
// is mounted first in api-app.ts and parks the presented value here.
const presentedSecrets = new WeakMap<Request, string>();

export function consumeProxyAuthSecret(
  req: Request,
  _res: Response,
  next: NextFunction,
): void {
  const name = config.PROXY_AUTH_SECRET_HEADER;
  const value = req.get(name);
  if (value !== undefined) {
    presentedSecrets.set(req, value);
    Reflect.deleteProperty(req.headers, name);
    const scrubbed = req.rawHeaders.map((v, i, raw) =>
      i % 2 === 1 && raw.at(i - 1)?.toLowerCase() === name ? '[REDACTED]' : v,
    );
    req.rawHeaders.splice(0, req.rawHeaders.length, ...scrubbed);
  }
  next();
}

function presentedSecret(req: Request): string {
  return (
    presentedSecrets.get(req) ?? req.get(config.PROXY_AUTH_SECRET_HEADER) ?? ''
  );
}

function sharedSecretOk(req: Request): boolean {
  const got = presentedSecret(req);
  const currentMatches = secretEqual(got, config.PROXY_AUTH_SHARED_SECRET);
  const previousMatches = secretEqual(
    got,
    config.PROXY_AUTH_SHARED_SECRET_PREVIOUS,
  );
  return currentMatches || previousMatches;
}

function secretEqual(got: string, expected: string): boolean {
  if (!expected) return false;
  const a = Buffer.from(got);
  const b = Buffer.from(expected);
  // Length check first; timingSafeEqual throws on unequal lengths.
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// The gate-asserted email, iff proxy auth is enabled, a configured current or
// previous secret matches, and the header carries exactly one well-formed
// address.
// Returns null otherwise, so the identity header is ignored and the caller
// falls back to normal session / 401 handling. Returns null when proxy auth is
// disabled, which keeps stock behavior byte-for-byte.
export function getProxyAuthEmail(req: Request): string | null {
  if (!config.IS_PROXY_AUTH_ENABLED) return null;
  if (!sharedSecretOk(req)) return null;
  const raw = req.get(config.PROXY_AUTH_HEADER);
  if (!raw) return null;
  const email = raw.trim().toLowerCase();
  if (!email || hasControlChar(email) || !isWellFormedEmail(email)) return null;
  return email;
}

function isEmailDomainAllowed(email: string): boolean {
  const domain = email.slice(email.lastIndexOf('@') + 1);
  return config.PROXY_AUTH_ALLOWED_EMAIL_DOMAINS.includes(domain);
}

async function findOrCreateUser(
  email: string,
  teamId: UserDocument['team'],
): Promise<UserDocument> {
  const existing = await findUserByEmail(email);
  if (existing) return existing;
  try {
    // Passwordless: no salt/hash, so /login/password can never authenticate
    // these users -- they exist only to back the gate-asserted session.
    const created = (await User.create({
      email,
      name: email,
      team: teamId,
    })) as UserDocument;
    // Distinct, structured event: a brand-new identity was just admitted by the
    // gate -- auditable separately from a normal returning-user login.
    logger.warn(
      { email, type: 'user_provision', authType: 'proxy' },
      'proxy-auth: provisioned a new user from the gate-asserted identity',
    );
    return created;
  } catch (err: any) {
    // Lost a create race against a concurrent first request from the same user
    // (unique email index). The winner created it; re-read.
    if (err?.code === 11000) {
      const u = await findUserByEmail(email);
      if (u) return u;
    }
    throw err;
  }
}

// True iff the gate vouched for this request (getProxyAuthEmail() non-null) AND
// the current session already belongs to that same identity.
export function hasProxyAuthSession(req: Request): boolean {
  const email = getProxyAuthEmail(req);
  return (
    email !== null &&
    req.isAuthenticated() &&
    req.user?.email?.toLowerCase() === email
  );
}

// Proxy mode with no matching session. Every request must carry a gate-vouched
// identity: a bare session is never honored, so a stolen or long-lived cookie
// cannot outlive the gate's session or an Authentik revocation (401). With a
// vouched identity, (re)establish the session as that user, then hand control to
// onEstablished (the caller's stock authenticated path). onEstablished only runs
// once the session provably matches the gate identity, so re-entering the
// caller cannot loop back here.
export function establishProxyAuthSession(
  req: Request,
  res: Response,
  next: NextFunction,
  onEstablished: () => void,
): void {
  const email = getProxyAuthEmail(req);
  if (!email) {
    res.sendStatus(401);
    return;
  }
  proxyHeaderAuth(
    req,
    res,
    err => {
      if (err) return next(err);
      if (!hasProxyAuthSession(req)) {
        res.sendStatus(401);
        return;
      }
      onEstablished();
    },
    email,
  ).catch(next);
}

// Establish a HyperDX session from the gate-asserted identity. Only called when
// getProxyAuthEmail() returned a value (proxy auth on + secret ok + valid email).
export async function proxyHeaderAuth(
  req: Request,
  res: Response,
  next: NextFunction,
  email: string,
): Promise<void> {
  if (!isEmailDomainAllowed(email)) {
    logger.warn(
      { email, type: 'user_login', authType: 'proxy' },
      'proxy-auth denied: email domain not in PROXY_AUTH_ALLOWED_EMAIL_DOMAINS',
    );
    res.sendStatus(403);
    return;
  }

  // HyperDX OSS is single-team; new SSO users join the existing team. If no team
  // exists yet we cannot provision -> let the normal /register or /team/setup
  // flow create the first team + owner.
  const team = await Team.findOne({});
  if (!team) {
    logger.warn('proxy-auth: no team exists yet; cannot provision SSO user');
    res.sendStatus(401);
    return;
  }

  const user = await findOrCreateUser(email, team._id);

  req.login(user, err => {
    if (err) return next(err);
    logger.info({
      message: `Proxy-auth login for "${email}"`,
      type: 'user_login',
      authType: 'proxy',
    });
    next();
  });
}
