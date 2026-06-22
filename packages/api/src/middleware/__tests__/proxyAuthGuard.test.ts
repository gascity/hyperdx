// gascity fork: unit tests for the proxy-auth hook in isUserAuthenticated
// (middleware/auth.ts) -- the request-level decision table. Heavy deps are
// mocked so these stay DB-free: a request either carries a gate-vouched
// identity (shared secret + well-formed email header) or it gets a 401, a bare
// session is never honored in proxy mode, and a vouched request always ends on
// the stock authenticated path (business context + query attribution).
/* eslint-disable @typescript-eslint/no-unsafe-type-assertion -- partial Express/mongoose test doubles */
import type { NextFunction, Request, Response } from 'express';

import * as config from '@/config';
import { findUserByEmail } from '@/controllers/user';
import { isUserAuthenticated } from '@/middleware/auth';
import Team from '@/models/team';
import User from '@/models/user';
import { setBusinessContext } from '@/utils/instrumentation';

jest.mock('@/config', () => ({
  __esModule: true,
  IS_LOCAL_APP_MODE: false,
  IS_PROXY_AUTH_ENABLED: true,
  PROXY_AUTH_HEADER: 'x-auth-request-email',
  PROXY_AUTH_SHARED_SECRET: 'current-s3cret-value',
  PROXY_AUTH_SECRET_HEADER: 'x-hdx-proxy-auth-secret',
  PROXY_AUTH_ALLOWED_EMAIL_DOMAINS: ['gascity.com'],
  FRONTEND_REDIRECT_BASE: '',
}));
jest.mock('@/controllers/user', () => ({
  findUserByEmail: jest.fn(),
  findUserByAccessKey: jest.fn(),
}));
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
jest.mock('@/utils/instrumentation', () => ({
  getActiveTraceId: jest.fn(() => undefined),
  getStaticFeatureFlags: jest.fn(() => ({})),
  setBusinessContext: jest.fn(),
}));
jest.mock('@hyperdx/common-utils/dist/clickhouse/node', () => ({
  withQueryAttribution: jest.fn((_ctx: unknown, fn: () => void) => fn()),
}));

const cfg = config as unknown as { IS_PROXY_AUTH_ENABLED: boolean };
const SECRET = 'current-s3cret-value';
const GATE_HEADERS = {
  'x-auth-request-email': 'Alice@GasCity.com',
  'x-hdx-proxy-auth-secret': SECRET,
};

type SessionUser = { _id: string; email: string; team: string };

type MockReq = {
  baseUrl: string;
  user?: SessionUser;
  get: (name: string) => string | undefined;
  isAuthenticated: () => boolean;
  login: jest.Mock;
};

function harness(headers: Record<string, string>, sessionUser?: SessionUser) {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  const mock: MockReq = {
    baseUrl: '/me',
    user: sessionUser,
    get: name => lower[name.toLowerCase()],
    isAuthenticated: () => mock.user != null,
    login: jest.fn((user: SessionUser, cb: (err: unknown) => void) => {
      mock.user = user;
      cb(null);
    }),
  };
  const req = mock as unknown as Request;
  const res = { sendStatus: jest.fn() } as unknown as Response;
  const next = jest.fn() as unknown as NextFunction & jest.Mock;
  return { mock, req, res, next };
}

// The proxy-auth path is async (DB lookups + req.login callback).
const settle = () => new Promise(resolve => setImmediate(resolve));

const alice: SessionUser = {
  _id: 'u-alice',
  email: 'alice@gascity.com',
  team: 'team1',
};
const bob: SessionUser = {
  _id: 'u-bob',
  email: 'bob@gascity.com',
  team: 'team1',
};

beforeEach(() => {
  cfg.IS_PROXY_AUTH_ENABLED = true;
  jest.clearAllMocks();
  (Team.findOne as jest.Mock).mockResolvedValue({ _id: 'team1' });
  (findUserByEmail as jest.Mock).mockImplementation(async (email: string) =>
    email === alice.email ? alice : null,
  );
});

describe('isUserAuthenticated in proxy-auth mode', () => {
  it('401s a bare session that carries no gate identity', () => {
    const { req, res, next } = harness({}, alice);
    isUserAuthenticated(req, res, next);
    expect(res.sendStatus).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('401s when the identity header arrives without the shared secret', () => {
    const { req, res, next } = harness(
      { 'x-auth-request-email': 'alice@gascity.com' },
      alice,
    );
    isUserAuthenticated(req, res, next);
    expect(res.sendStatus).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('401s when the shared secret is wrong', () => {
    const { req, res, next } = harness({
      'x-auth-request-email': 'alice@gascity.com',
      'x-hdx-proxy-auth-secret': 'wrong-s3cret-value!!',
    });
    isUserAuthenticated(req, res, next);
    expect(res.sendStatus).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('continues on the stock path when the session already matches', () => {
    const { mock, req, res, next } = harness(GATE_HEADERS, alice);
    isUserAuthenticated(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
    expect(mock.login).not.toHaveBeenCalled();
    expect(setBusinessContext).toHaveBeenCalledWith(
      expect.objectContaining({ userId: 'u-alice', email: alice.email }),
    );
  });

  it('establishes a session for an existing user, then takes the stock path', async () => {
    const { mock, req, res, next } = harness(GATE_HEADERS);
    isUserAuthenticated(req, res, next);
    await settle();
    expect(mock.login).toHaveBeenCalledTimes(1);
    expect(mock.user).toBe(alice);
    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
    expect(setBusinessContext).toHaveBeenCalledWith(
      expect.objectContaining({ userId: 'u-alice' }),
    );
  });

  it('replaces a session that belongs to a different identity', async () => {
    const { mock, req, res, next } = harness(GATE_HEADERS, bob);
    isUserAuthenticated(req, res, next);
    await settle();
    expect(mock.login).toHaveBeenCalledTimes(1);
    expect(mock.user).toBe(alice);
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('provisions a first-time user into the existing team', async () => {
    const carol = { _id: 'u-carol', email: 'carol@gascity.com', team: 'team1' };
    (User.create as jest.Mock).mockResolvedValue(carol);
    const { mock, req, res, next } = harness({
      'x-auth-request-email': 'carol@gascity.com',
      'x-hdx-proxy-auth-secret': SECRET,
    });
    isUserAuthenticated(req, res, next);
    await settle();
    expect(User.create).toHaveBeenCalledWith({
      email: 'carol@gascity.com',
      name: 'carol@gascity.com',
      team: 'team1',
    });
    expect(mock.user).toBe(carol);
    expect(next).toHaveBeenCalledWith();
  });

  it('403s an identity outside the allowed email domains', async () => {
    const { req, res, next } = harness({
      'x-auth-request-email': 'mallory@evil.com',
      'x-hdx-proxy-auth-secret': SECRET,
    });
    isUserAuthenticated(req, res, next);
    await settle();
    expect(res.sendStatus).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it('passes a login failure to the error handler', async () => {
    const { mock, req, res, next } = harness(GATE_HEADERS);
    mock.login.mockImplementation((_u: unknown, cb: (err: unknown) => void) =>
      cb(new Error('boom')),
    );
    isUserAuthenticated(req, res, next);
    await settle();
    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });

  it('never loops when the logged-in user does not match the gate identity', async () => {
    (findUserByEmail as jest.Mock).mockResolvedValue({
      ...bob,
      email: 'someone-else@gascity.com',
    });
    const { mock, req, res, next } = harness(GATE_HEADERS);
    isUserAuthenticated(req, res, next);
    await settle();
    expect(mock.login).toHaveBeenCalledTimes(1);
    expect(res.sendStatus).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });
});

describe('isUserAuthenticated with proxy auth disabled (stock behavior)', () => {
  beforeEach(() => {
    cfg.IS_PROXY_AUTH_ENABLED = false;
  });

  it('honors a normal session and ignores gate headers', () => {
    const { mock, req, res, next } = harness(
      { 'x-auth-request-email': 'bob@gascity.com' },
      alice,
    );
    isUserAuthenticated(req, res, next);
    expect(next).toHaveBeenCalledWith();
    expect(mock.user).toBe(alice);
    expect(mock.login).not.toHaveBeenCalled();
  });

  it('401s without a session even when gate headers are present', () => {
    const { mock, req, res, next } = harness(GATE_HEADERS);
    isUserAuthenticated(req, res, next);
    expect(res.sendStatus).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
    expect(mock.login).not.toHaveBeenCalled();
  });
});
