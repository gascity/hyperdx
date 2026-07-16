describe('config', () => {
  describe('FRONTEND_REDIRECT_BASE', () => {
    const ORIGINAL_INLINE = process.env.HDX_PREVIEW_INLINE_API;
    const ORIGINAL_FRONTEND_URL = process.env.FRONTEND_URL;

    afterEach(() => {
      // Restore the original env vars so other tests in the suite see the
      // values they expect.
      if (ORIGINAL_INLINE === undefined) {
        delete process.env.HDX_PREVIEW_INLINE_API;
      } else {
        process.env.HDX_PREVIEW_INLINE_API = ORIGINAL_INLINE;
      }
      if (ORIGINAL_FRONTEND_URL === undefined) {
        delete process.env.FRONTEND_URL;
      } else {
        process.env.FRONTEND_URL = ORIGINAL_FRONTEND_URL;
      }
      jest.resetModules();
    });

    it('falls back to FRONTEND_URL when HDX_PREVIEW_INLINE_API is not set', () => {
      delete process.env.HDX_PREVIEW_INLINE_API;
      process.env.FRONTEND_URL = 'https://hyperdx.io';

      jest.isolateModules(() => {
        // eslint-disable-next-line @typescript-eslint/no-require-imports, n/no-missing-require
        const config = require('@/config');
        expect(config.IS_INLINE_API).toBe(false);
        expect(config.FRONTEND_REDIRECT_BASE).toBe('https://hyperdx.io');
        expect(config.FRONTEND_REDIRECT_BASE).toBe(config.FRONTEND_URL);
      });
    });

    it('falls back to FRONTEND_URL when HDX_PREVIEW_INLINE_API is "false"', () => {
      process.env.HDX_PREVIEW_INLINE_API = 'false';
      process.env.FRONTEND_URL = 'https://hyperdx.io';

      jest.isolateModules(() => {
        // eslint-disable-next-line @typescript-eslint/no-require-imports, n/no-missing-require
        const config = require('@/config');
        expect(config.IS_INLINE_API).toBe(false);
        expect(config.FRONTEND_REDIRECT_BASE).toBe('https://hyperdx.io');
      });
    });

    it('emits an empty string (relative redirects) when HDX_PREVIEW_INLINE_API is "true"', () => {
      process.env.HDX_PREVIEW_INLINE_API = 'true';
      process.env.FRONTEND_URL = 'https://private.hyperdx.io';

      jest.isolateModules(() => {
        // eslint-disable-next-line @typescript-eslint/no-require-imports, n/no-missing-require
        const config = require('@/config');
        expect(config.IS_INLINE_API).toBe(true);
        expect(config.FRONTEND_REDIRECT_BASE).toBe('');
        // Sanity check: FRONTEND_URL itself is unchanged so emails/SAML
        // callbacks still have the absolute origin available when needed.
        expect(config.FRONTEND_URL).toBe('https://private.hyperdx.io');
      });
    });
  });

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
});
