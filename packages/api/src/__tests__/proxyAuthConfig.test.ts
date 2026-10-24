// gascity fork: startup-validation tests for the proxy-auth config
// (config.ts). Kept in a fork-owned file so upstream's config.test.ts stays
// untouched (it conflicted on every rebase when we appended to it).
/* eslint-disable security/detect-object-injection -- env names are test constants */
describe('proxy auth shared-secret rotation', () => {
  type ProxyAuthConfig = {
    PROXY_AUTH_SHARED_SECRET: string;
    PROXY_AUTH_SHARED_SECRET_PREVIOUS: string;
  };

  const ORIGINAL_PROXY_AUTH_ENABLED = process.env.PROXY_AUTH_ENABLED;
  const ORIGINAL_SHARED_SECRET = process.env.PROXY_AUTH_SHARED_SECRET;
  const ORIGINAL_PREVIOUS_SHARED_SECRET =
    process.env.PROXY_AUTH_SHARED_SECRET_PREVIOUS;

  function restoreEnv(name: string, value: string | undefined) {
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }

  function loadConfig(): ProxyAuthConfig {
    let config: ProxyAuthConfig | undefined;
    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports, n/no-missing-require
      config = require('@/config');
    });
    if (!config) throw new Error('config module did not load');
    return config;
  }

  afterEach(() => {
    restoreEnv('PROXY_AUTH_ENABLED', ORIGINAL_PROXY_AUTH_ENABLED);
    restoreEnv('PROXY_AUTH_SHARED_SECRET', ORIGINAL_SHARED_SECRET);
    restoreEnv(
      'PROXY_AUTH_SHARED_SECRET_PREVIOUS',
      ORIGINAL_PREVIOUS_SHARED_SECRET,
    );
    jest.resetModules();
  });

  it('keeps proxy-disabled startup behavior when neither secret is configured', () => {
    process.env.PROXY_AUTH_ENABLED = 'false';
    delete process.env.PROXY_AUTH_SHARED_SECRET;
    delete process.env.PROXY_AUTH_SHARED_SECRET_PREVIOUS;

    expect(() => loadConfig()).not.toThrow();
  });

  it('leaves rotation-value validation inert when proxy auth is disabled', () => {
    process.env.PROXY_AUTH_ENABLED = 'false';
    process.env.PROXY_AUTH_SHARED_SECRET = 'same-disabled-value';
    process.env.PROXY_AUTH_SHARED_SECRET_PREVIOUS = 'same-disabled-value';

    expect(() => loadConfig()).not.toThrow();
  });

  it('requires the current secret even when a previous secret is configured', () => {
    const previousSecret = 'previous-value-must-not-leak';
    process.env.PROXY_AUTH_ENABLED = 'true';
    delete process.env.PROXY_AUTH_SHARED_SECRET;
    process.env.PROXY_AUTH_SHARED_SECRET_PREVIOUS = previousSecret;

    let error: unknown;
    try {
      loadConfig();
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toContain(previousSecret);
  });

  it('starts with distinct current and previous secrets', () => {
    process.env.PROXY_AUTH_ENABLED = 'true';
    process.env.PROXY_AUTH_SHARED_SECRET = 'current-s3cret-value';
    process.env.PROXY_AUTH_SHARED_SECRET_PREVIOUS = 'previous-s3cret-value';

    const config = loadConfig();

    expect(config.PROXY_AUTH_SHARED_SECRET).toBe('current-s3cret-value');
    expect(config.PROXY_AUTH_SHARED_SECRET_PREVIOUS).toBe(
      'previous-s3cret-value',
    );
  });

  it('starts with an empty previous secret when a current secret is configured', () => {
    process.env.PROXY_AUTH_ENABLED = 'true';
    process.env.PROXY_AUTH_SHARED_SECRET = 'current-s3cret-value';
    process.env.PROXY_AUTH_SHARED_SECRET_PREVIOUS = '';

    const config = loadConfig();

    expect(config.PROXY_AUTH_SHARED_SECRET).toBe('current-s3cret-value');
    expect(config.PROXY_AUTH_SHARED_SECRET_PREVIOUS).toBe('');
  });

  it('rejects equal current and previous secrets without leaking the value', () => {
    const sharedSecret = 'same-value-must-not-leak';
    process.env.PROXY_AUTH_ENABLED = 'true';
    process.env.PROXY_AUTH_SHARED_SECRET = sharedSecret;
    process.env.PROXY_AUTH_SHARED_SECRET_PREVIOUS = sharedSecret;

    let error: unknown;
    try {
      loadConfig();
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toContain(sharedSecret);
  });
});

// The bundled OpenTelemetry SDK's advanced network capture records every
// incoming request header on the server span as the request arrives, before
// consumeProxyAuthSecret runs, and exports it. Proxy auth must not start with
// it on. The accepted spellings mirror the SDK's own boolean parsing.
describe('proxy auth with advanced network capture', () => {
  const ORIGINAL = {
    PROXY_AUTH_ENABLED: process.env.PROXY_AUTH_ENABLED,
    PROXY_AUTH_SHARED_SECRET: process.env.PROXY_AUTH_SHARED_SECRET,
    PROXY_AUTH_SHARED_SECRET_PREVIOUS:
      process.env.PROXY_AUTH_SHARED_SECRET_PREVIOUS,
    HDX_NODE_ADVANCED_NETWORK_CAPTURE:
      process.env.HDX_NODE_ADVANCED_NETWORK_CAPTURE,
  };
  const SECRET = 'capture-guard-secret-must-not-leak';

  function loadWithCapture(enabled: string, capture: string | undefined) {
    process.env.PROXY_AUTH_ENABLED = enabled;
    process.env.PROXY_AUTH_SHARED_SECRET = SECRET;
    delete process.env.PROXY_AUTH_SHARED_SECRET_PREVIOUS;
    if (capture === undefined) {
      delete process.env.HDX_NODE_ADVANCED_NETWORK_CAPTURE;
    } else {
      process.env.HDX_NODE_ADVANCED_NETWORK_CAPTURE = capture;
    }
    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports, n/no-missing-require
      require('@/config');
    });
  }

  afterEach(() => {
    for (const [name, value] of Object.entries(ORIGINAL)) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
    jest.resetModules();
  });

  it.each(['true', '1', 'YES', ' True '])(
    'refuses to start when capture is %p, without leaking the secret',
    capture => {
      let error: unknown;
      try {
        loadWithCapture('true', capture);
      } catch (caught) {
        error = caught;
      }

      expect(error).toBeInstanceOf(Error);
      expect(String(error)).toContain('HDX_NODE_ADVANCED_NETWORK_CAPTURE');
      expect(String(error)).not.toContain(SECRET);
    },
  );

  it.each([undefined, '', 'false', '0', 'no'])(
    'starts when capture is %p',
    capture => {
      expect(() => loadWithCapture('true', capture)).not.toThrow();
    },
  );

  it('leaves the capture check inert when proxy auth is disabled', () => {
    expect(() => loadWithCapture('false', 'true')).not.toThrow();
  });
});
