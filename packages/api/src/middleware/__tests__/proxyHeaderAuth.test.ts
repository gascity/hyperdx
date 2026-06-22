// gascity fork: unit tests for the proxy-header SSO entry point. The heavy deps
// (config, models, controllers, logger) are mocked so importing the middleware
// never registers a mongoose model or reads real env -- these are pure tests of
// the security-critical header parsing, the shared-secret check, and the auth
// branches (domain allowlist / no-team / existing user).
import type { Request, Response } from 'express';

import * as config from '@/config';
import { findUserByEmail } from '@/controllers/user';
import {
  getProxyAuthEmail,
  proxyHeaderAuth,
} from '@/middleware/proxyHeaderAuth';
import Team from '@/models/team';

jest.mock('@/config', () => ({
  __esModule: true,
  IS_PROXY_AUTH_ENABLED: true,
  PROXY_AUTH_HEADER: 'x-auth-request-email',
  PROXY_AUTH_SHARED_SECRET: '',
  PROXY_AUTH_SECRET_HEADER: 'x-hdx-proxy-auth-secret',
  PROXY_AUTH_ALLOWED_EMAIL_DOMAINS: ['gascity.com'],
}));
jest.mock('@/controllers/user', () => ({ findUserByEmail: jest.fn() }));
jest.mock('@/models/user', () => ({
  __esModule: true,
  default: { create: jest.fn() },
}));
jest.mock('@/models/team', () => ({
  __esModule: true,
  default: { findOne: jest.fn() },
}));
jest.mock('@/utils/logger', () => ({
  __esModule: true,
  default: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

const cfg = config as unknown as {
  IS_PROXY_AUTH_ENABLED: boolean;
  PROXY_AUTH_HEADER: string;
  PROXY_AUTH_SHARED_SECRET: string;
  PROXY_AUTH_SECRET_HEADER: string;
  PROXY_AUTH_ALLOWED_EMAIL_DOMAINS: string[];
};

function reqWith(headers: Record<string, string>): Request {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return {
    get: (name: string): string | undefined => lower[name.toLowerCase()],
  } as unknown as Request;
}

beforeEach(() => {
  cfg.IS_PROXY_AUTH_ENABLED = true;
  cfg.PROXY_AUTH_HEADER = 'x-auth-request-email';
  cfg.PROXY_AUTH_SHARED_SECRET = '';
  cfg.PROXY_AUTH_SECRET_HEADER = 'x-hdx-proxy-auth-secret';
  cfg.PROXY_AUTH_ALLOWED_EMAIL_DOMAINS = ['gascity.com'];
  jest.clearAllMocks();
});

describe('getProxyAuthEmail', () => {
  it('returns null when proxy auth is disabled', () => {
    cfg.IS_PROXY_AUTH_ENABLED = false;
    expect(
      getProxyAuthEmail(reqWith({ 'x-auth-request-email': 'a@gascity.com' })),
    ).toBeNull();
  });

  it('returns the trimmed + lowercased email when enabled (no secret)', () => {
    expect(
      getProxyAuthEmail(
        reqWith({ 'x-auth-request-email': '  Julian@GasCity.com ' }),
      ),
    ).toBe('julian@gascity.com');
  });

  it('returns null when the header is absent', () => {
    expect(getProxyAuthEmail(reqWith({}))).toBeNull();
  });

  it('rejects a multi-valued (comma) header', () => {
    expect(
      getProxyAuthEmail(
        reqWith({ 'x-auth-request-email': 'a@gascity.com,b@evil.com' }),
      ),
    ).toBeNull();
  });

  it('rejects malformed emails', () => {
    for (const v of [
      'notanemail',
      'no@domain',
      '@gascity.com',
      'a b@gascity.com',
      'a@gascity',
    ]) {
      expect(
        getProxyAuthEmail(reqWith({ 'x-auth-request-email': v })),
      ).toBeNull();
    }
  });

  it('rejects control characters in the local part (not just whitespace)', () => {
    // U+0001 is a control char NOT matched by \s, so it would slip past a naive
    // [^\s@] class -- the L-1 fix excludes \x00-\x1f explicitly.
    const ctrlEmail = `a${String.fromCharCode(1)}b@gascity.com`;
    expect(
      getProxyAuthEmail(reqWith({ 'x-auth-request-email': ctrlEmail })),
    ).toBeNull();
  });

  describe('with a shared secret configured', () => {
    beforeEach(() => {
      cfg.PROXY_AUTH_SHARED_SECRET = 's3cret-value';
    });

    it('returns the email when the secret header matches', () => {
      expect(
        getProxyAuthEmail(
          reqWith({
            'x-auth-request-email': 'a@gascity.com',
            'x-hdx-proxy-auth-secret': 's3cret-value',
          }),
        ),
      ).toBe('a@gascity.com');
    });

    it('returns null when the secret header is missing', () => {
      expect(
        getProxyAuthEmail(reqWith({ 'x-auth-request-email': 'a@gascity.com' })),
      ).toBeNull();
    });

    it('returns null (no throw) on a wrong or different-length secret', () => {
      expect(
        getProxyAuthEmail(
          reqWith({
            'x-auth-request-email': 'a@gascity.com',
            'x-hdx-proxy-auth-secret': 'wrong',
          }),
        ),
      ).toBeNull();
      expect(
        getProxyAuthEmail(
          reqWith({
            'x-auth-request-email': 'a@gascity.com',
            'x-hdx-proxy-auth-secret': 's3cret-value-longer',
          }),
        ),
      ).toBeNull();
    });
  });
});

describe('proxyHeaderAuth', () => {
  function harness() {
    const res = { sendStatus: jest.fn() } as unknown as Response;
    const next = jest.fn();
    const req = {
      login: jest.fn((_u: unknown, cb: (e: unknown) => void) => cb(null)),
    } as unknown as Request;
    return { req, res, next };
  }

  it('403s when the email domain is not allowed', async () => {
    const { req, res, next } = harness();
    await proxyHeaderAuth(req, res, next, 'a@evil.com');
    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it('401s when no team exists yet', async () => {
    (Team.findOne as jest.Mock).mockResolvedValue(null);
    (findUserByEmail as jest.Mock).mockResolvedValue(null);
    const { req, res, next } = harness();
    await proxyHeaderAuth(req, res, next, 'a@gascity.com');
    expect(res.sendStatus).toHaveBeenCalledWith(401);
  });

  it('logs in an existing user and calls next', async () => {
    (Team.findOne as jest.Mock).mockResolvedValue({ _id: 'team1' });
    (findUserByEmail as jest.Mock).mockResolvedValue({
      _id: 'u1',
      email: 'a@gascity.com',
    });
    const { req, res, next } = harness();
    await proxyHeaderAuth(req, res, next, 'a@gascity.com');
    expect(req.login).toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith();
  });
});
