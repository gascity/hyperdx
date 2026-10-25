// gascity fork: unit tests for the proxy-header SSO entry point. The heavy deps
// (config, models, controllers, logger) are mocked so importing the middleware
// never registers a mongoose model or reads real env -- these are pure tests of
// the security-critical header parsing, the shared-secret check, and the auth
// branches (domain allowlist / no-team / existing user).
/* eslint-disable @typescript-eslint/no-unsafe-type-assertion, security/detect-object-injection -- partial Express/mongoose test doubles */
import type { Request, Response } from 'express';

import * as config from '@/config';
import { findUserByEmail } from '@/controllers/user';
import {
  consumeProxyAuthSecret,
  getProxyAuthEmail,
  proxyHeaderAuth,
} from '@/middleware/proxyHeaderAuth';
import Team from '@/models/team';
import logger from '@/utils/logger';

jest.mock('@/config', () => ({
  __esModule: true,
  IS_PROXY_AUTH_ENABLED: true,
  PROXY_AUTH_HEADER: 'x-auth-request-email',
  PROXY_AUTH_SHARED_SECRET: '',
  PROXY_AUTH_SHARED_SECRET_PREVIOUS: '',
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
  PROXY_AUTH_SHARED_SECRET_PREVIOUS: string;
  PROXY_AUTH_SECRET_HEADER: string;
  PROXY_AUTH_ALLOWED_EMAIL_DOMAINS: string[];
};
const CURRENT_SECRET = 'current-s3cret-value';

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
  cfg.PROXY_AUTH_SHARED_SECRET = CURRENT_SECRET;
  cfg.PROXY_AUTH_SHARED_SECRET_PREVIOUS = '';
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

  it('returns null when neither shared secret is configured', () => {
    cfg.PROXY_AUTH_SHARED_SECRET = '';

    expect(
      getProxyAuthEmail(
        reqWith({ 'x-auth-request-email': '  Julian@GasCity.com ' }),
      ),
    ).toBeNull();
  });

  it('returns the trimmed and lowercased email after current-secret authentication', () => {
    expect(
      getProxyAuthEmail(
        reqWith({
          'x-auth-request-email': '  Julian@GasCity.com ',
          'x-hdx-proxy-auth-secret': CURRENT_SECRET,
        }),
      ),
    ).toBe('julian@gascity.com');
  });

  it('returns null when the header is absent', () => {
    expect(
      getProxyAuthEmail(reqWith({ 'x-hdx-proxy-auth-secret': CURRENT_SECRET })),
    ).toBeNull();
  });

  it('rejects a multi-valued (comma) header', () => {
    expect(
      getProxyAuthEmail(
        reqWith({
          'x-auth-request-email': 'a@gascity.com,b@evil.com',
          'x-hdx-proxy-auth-secret': CURRENT_SECRET,
        }),
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
        getProxyAuthEmail(
          reqWith({
            'x-auth-request-email': v,
            'x-hdx-proxy-auth-secret': CURRENT_SECRET,
          }),
        ),
      ).toBeNull();
    }
  });

  it('rejects empty domain labels', () => {
    for (const v of ['a@gascity..com', 'a@.gascity.com', 'a@gascity.com.']) {
      expect(
        getProxyAuthEmail(
          reqWith({
            'x-auth-request-email': v,
            'x-hdx-proxy-auth-secret': CURRENT_SECRET,
          }),
        ),
      ).toBeNull();
    }
  });

  it('accepts a multi-label domain', () => {
    expect(
      getProxyAuthEmail(
        reqWith({
          'x-auth-request-email': 'a.b@eng.gascity.com',
          'x-hdx-proxy-auth-secret': CURRENT_SECRET,
        }),
      ),
    ).toBe('a.b@eng.gascity.com');
  });

  it('rejects addresses longer than the RFC 5321 limit of 254', () => {
    const tooLong = `${'a'.repeat(64)}@${'b'.repeat(180)}.gascity.com`;
    expect(tooLong.length).toBeGreaterThan(254);
    expect(
      getProxyAuthEmail(
        reqWith({
          'x-auth-request-email': tooLong,
          'x-hdx-proxy-auth-secret': CURRENT_SECRET,
        }),
      ),
    ).toBeNull();
  });

  it('rejects a pathological dotted domain in linear time', () => {
    // A domain of many dots that fails at the end is quadratic for an ambiguous
    // pattern (a label class that also matches '.'): about 5 s for this input
    // with the previous single-regex check.
    const hostile = `a@${'.'.repeat(50_000)}@`;
    const started = Date.now();
    expect(
      getProxyAuthEmail(
        reqWith({
          'x-auth-request-email': hostile,
          'x-hdx-proxy-auth-secret': CURRENT_SECRET,
        }),
      ),
    ).toBeNull();
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it('rejects control characters in the local part (not just whitespace)', () => {
    // U+0001 is a control char NOT matched by \s, so it would slip past a naive
    // [^\s@] class -- the L-1 fix excludes \x00-\x1f explicitly.
    const ctrlEmail = `a${String.fromCharCode(1)}b@gascity.com`;
    expect(
      getProxyAuthEmail(
        reqWith({
          'x-auth-request-email': ctrlEmail,
          'x-hdx-proxy-auth-secret': CURRENT_SECRET,
        }),
      ),
    ).toBeNull();
  });

  describe('with a shared secret configured', () => {
    beforeEach(() => {
      cfg.PROXY_AUTH_SHARED_SECRET = 's3cret-value';
    });

    it('returns the email when the current secret matches with no previous secret', () => {
      expect(
        getProxyAuthEmail(
          reqWith({
            'x-auth-request-email': 'a@gascity.com',
            'x-hdx-proxy-auth-secret': 's3cret-value',
          }),
        ),
      ).toBe('a@gascity.com');
    });

    it('returns the email when the current secret matches during overlap', () => {
      cfg.PROXY_AUTH_SHARED_SECRET_PREVIOUS = 'previous-s3cret-value';

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

    it('returns null when the secret header is empty', () => {
      expect(
        getProxyAuthEmail(
          reqWith({
            'x-auth-request-email': 'a@gascity.com',
            'x-hdx-proxy-auth-secret': '',
          }),
        ),
      ).toBeNull();
    });

    it('returns null when the secret header is wrong', () => {
      const rejectedSecret = 'wrong-secret-must-not-leak';
      cfg.PROXY_AUTH_SHARED_SECRET_PREVIOUS = 'previous-s3cret-value';

      expect(
        getProxyAuthEmail(
          reqWith({
            'x-auth-request-email': 'a@gascity.com',
            'x-hdx-proxy-auth-secret': rejectedSecret,
          }),
        ),
      ).toBeNull();
      for (const method of ['info', 'warn', 'error', 'debug'] as const) {
        expect(logger[method]).not.toHaveBeenCalled();
      }
    });

    it('returns null without throwing when the secret has a different length', () => {
      cfg.PROXY_AUTH_SHARED_SECRET_PREVIOUS = 'previous-s3cret-value';

      expect(
        getProxyAuthEmail(
          reqWith({
            'x-auth-request-email': 'a@gascity.com',
            'x-hdx-proxy-auth-secret': 'short',
          }),
        ),
      ).toBeNull();
    });

    it('returns the email when the previous secret header matches', () => {
      cfg.PROXY_AUTH_SHARED_SECRET_PREVIOUS = 'previous-s3cret-value';

      expect(
        getProxyAuthEmail(
          reqWith({
            'x-auth-request-email': 'a@gascity.com',
            'x-hdx-proxy-auth-secret': 'previous-s3cret-value',
          }),
        ),
      ).toBe('a@gascity.com');
    });

    it('rejects the old secret after the previous slot is cleared', () => {
      cfg.PROXY_AUTH_SHARED_SECRET = 'new-s3cret-value';
      cfg.PROXY_AUTH_SHARED_SECRET_PREVIOUS = '';

      expect(
        getProxyAuthEmail(
          reqWith({
            'x-auth-request-email': 'a@gascity.com',
            'x-hdx-proxy-auth-secret': 'old-s3cret-value',
          }),
        ),
      ).toBeNull();
    });
  });
});

describe('consumeProxyAuthSecret', () => {
  // A request shaped like Node's IncomingMessage + Express's req.get(): the
  // lowercased headers map, the raw name/value list, and a getter over headers.
  function rawReq(pairs: [string, string][]): Request {
    const headers: Record<string, string> = {};
    const rawHeaders: string[] = [];
    for (const [k, v] of pairs) {
      headers[k.toLowerCase()] = v;
      rawHeaders.push(k, v);
    }
    return {
      headers,
      rawHeaders,
      get: (name: string): string | undefined => headers[name.toLowerCase()],
    } as unknown as Request;
  }

  beforeEach(() => {
    cfg.PROXY_AUTH_SHARED_SECRET = CURRENT_SECRET;
  });

  it('takes the secret off headers and rawHeaders but keeps the rest', () => {
    const req = rawReq([
      ['X-Auth-Request-Email', 'a@gascity.com'],
      ['X-Hdx-Proxy-Auth-Secret', CURRENT_SECRET],
      ['Cookie', 'connect.sid=abc'],
    ]);
    const next = jest.fn();
    consumeProxyAuthSecret(req, {} as Response, next);
    expect(next).toHaveBeenCalledWith();
    expect(req.headers['x-hdx-proxy-auth-secret']).toBeUndefined();
    expect(req.rawHeaders).not.toContain(CURRENT_SECRET);
    expect(req.headers['x-auth-request-email']).toBe('a@gascity.com');
    expect(req.headers.cookie).toBe('connect.sid=abc');
  });

  it('still authenticates with the consumed secret', () => {
    const req = rawReq([
      ['x-auth-request-email', 'a@gascity.com'],
      ['x-hdx-proxy-auth-secret', CURRENT_SECRET],
    ]);
    consumeProxyAuthSecret(req, {} as Response, jest.fn());
    expect(getProxyAuthEmail(req)).toBe('a@gascity.com');
  });

  it('still rejects a wrong consumed secret', () => {
    const req = rawReq([
      ['x-auth-request-email', 'a@gascity.com'],
      ['x-hdx-proxy-auth-secret', 'wrong-s3cret-value!!'],
    ]);
    consumeProxyAuthSecret(req, {} as Response, jest.fn());
    expect(req.headers['x-hdx-proxy-auth-secret']).toBeUndefined();
    expect(getProxyAuthEmail(req)).toBeNull();
  });

  it('is a no-op without the secret header', () => {
    const req = rawReq([['x-auth-request-email', 'a@gascity.com']]);
    const next = jest.fn();
    consumeProxyAuthSecret(req, {} as Response, next);
    expect(next).toHaveBeenCalledWith();
    expect(req.rawHeaders).toEqual(['x-auth-request-email', 'a@gascity.com']);
    expect(getProxyAuthEmail(req)).toBeNull();
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
