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
// PROXY_AUTH_SHARED_SECRET is a strong in-app backstop (a value the browser
// never sees, so it survives an edge header-strip misconfig). The email-domain
// allowlist is defense-in-depth, never the primary control.
import crypto from 'crypto';
import type { NextFunction, Request, Response } from 'express';

import * as config from '@/config';
import { findUserByEmail } from '@/controllers/user';
import Team from '@/models/team';
import User, { type UserDocument } from '@/models/user';
import logger from '@/utils/logger';

// Rejects obviously malformed values (a comma => a multi-valued header) before a
// DB lookup. This is hygiene, NOT the security control -- the gate asserts the
// authoritative, already-authenticated address.
const EMAIL_RE = /^[^\s@,]+@[^\s@,]+\.[^\s@,]+$/;

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

function sharedSecretOk(req: Request): boolean {
  const expected = config.PROXY_AUTH_SHARED_SECRET;
  // No secret configured -> rely solely on the edge (header strip + netpol).
  if (!expected) return true;
  const got = req.get(config.PROXY_AUTH_SECRET_HEADER) ?? '';
  const a = Buffer.from(got);
  const b = Buffer.from(expected);
  // Length check first; timingSafeEqual throws on unequal lengths.
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// The gate-asserted email, iff proxy auth is enabled, the (optional) shared
// secret matches, and the header carries exactly one well-formed address.
// Returns null otherwise, so the identity header is ignored and the caller
// falls back to normal session / 401 handling. Returns null when proxy auth is
// disabled, which keeps stock behavior byte-for-byte.
export function getProxyAuthEmail(req: Request): string | null {
  if (!config.IS_PROXY_AUTH_ENABLED) return null;
  if (!sharedSecretOk(req)) return null;
  const raw = req.get(config.PROXY_AUTH_HEADER);
  if (!raw) return null;
  const email = raw.trim().toLowerCase();
  if (!email || hasControlChar(email) || !EMAIL_RE.test(email)) return null;
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
