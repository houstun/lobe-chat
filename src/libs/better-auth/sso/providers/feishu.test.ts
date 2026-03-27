import { afterEach, describe, expect, it, vi } from 'vitest';

import provider from './feishu';

vi.mock('@/envs/auth', () => ({
  authEnv: {
    AUTH_FEISHU_EMAIL_MAP: undefined as string | undefined,
    AUTH_FEISHU_APP_ID: undefined as string | undefined,
    AUTH_FEISHU_APP_SECRET: undefined as string | undefined,
  },
}));

describe('feishu provider', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('prefers the real email from the token payload when user_info omits email fields', async () => {
    const config = provider.build({
      AUTH_FEISHU_APP_ID: 'app-id',
      AUTH_FEISHU_APP_SECRET: 'app-secret',
    });

    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      json: async () => ({
        code: 0,
        data: {
          name: 'Derek',
          open_id: 'ou_test',
          union_id: 'on_test',
        },
      }),
      ok: true,
    } as Response);

    const user = await config.getUserInfo?.({
      accessToken: 'token',
      raw: {
        code: 0,
        data: {
          access_token: 'token',
          email: 'derek@configreality.com',
          union_id: 'on_test',
        },
      },
    });

    expect(fetchMock).toHaveBeenCalled();
    expect(user).toMatchObject({
      email: 'derek@configreality.com',
      id: 'on_test',
      name: 'Derek',
    });
  });

  it('falls back to a synthetic email when Feishu does not expose any email field', async () => {
    const config = provider.build({
      AUTH_FEISHU_APP_ID: 'app-id',
      AUTH_FEISHU_APP_SECRET: 'app-secret',
    });

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      json: async () => ({
        code: 0,
        data: {
          name: 'Derek',
          union_id: 'on_test',
        },
      }),
      ok: true,
    } as Response);

    const user = await config.getUserInfo?.({
      accessToken: 'token',
      raw: {
        code: 0,
        data: {
          access_token: 'token',
          union_id: 'on_test',
        },
      },
    });

    expect(user).toMatchObject({
      email: 'on_test@feishu.sso',
      id: 'on_test',
    });
  });

  it('prefers the configured email map when Feishu omits all email fields', async () => {
    vi.resetModules();
    vi.doMock('@/envs/auth', () => ({
      authEnv: {
        AUTH_FEISHU_EMAIL_MAP: 'on_test=derek@configreality.com',
        AUTH_FEISHU_APP_ID: undefined as string | undefined,
        AUTH_FEISHU_APP_SECRET: undefined as string | undefined,
      },
    }));

    const { default: mappedProvider } = await import('./feishu');
    const config = mappedProvider.build({
      AUTH_FEISHU_APP_ID: 'app-id',
      AUTH_FEISHU_APP_SECRET: 'app-secret',
    });

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      json: async () => ({
        code: 0,
        data: {
          name: 'Derek',
          union_id: 'on_test',
        },
      }),
      ok: true,
    } as Response);

    const user = await config.getUserInfo?.({
      accessToken: 'token',
      raw: {
        code: 0,
        data: {
          access_token: 'token',
          union_id: 'on_test',
        },
      },
    });

    expect(user).toMatchObject({
      email: 'derek@configreality.com',
      id: 'on_test',
    });

    vi.doUnmock('@/envs/auth');
    vi.resetModules();
  });

  it('can still build the user from token payload when user_info is unavailable', async () => {
    const config = provider.build({
      AUTH_FEISHU_APP_ID: 'app-id',
      AUTH_FEISHU_APP_SECRET: 'app-secret',
    });

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
    } as Response);

    const user = await config.getUserInfo?.({
      accessToken: 'token',
      raw: {
        code: 0,
        data: {
          access_token: 'token',
          email: 'derek@configreality.com',
          name: 'Derek',
          union_id: 'on_test',
        },
      },
    });

    expect(user).toMatchObject({
      email: 'derek@configreality.com',
      id: 'on_test',
      name: 'Derek',
    });
  });

  it('falls back to the contact api when authen user_info omits the email', async () => {
    const config = provider.build({
      AUTH_FEISHU_APP_ID: 'app-id',
      AUTH_FEISHU_APP_SECRET: 'app-secret',
    });

    const fetchMock = vi.spyOn(globalThis, 'fetch');

    fetchMock
      .mockResolvedValueOnce({
        json: async () => ({
          code: 0,
          data: {
            name: 'Derek',
            union_id: 'on_test',
            user_id: 'ou_user',
          },
        }),
        ok: true,
      } as Response)
      .mockResolvedValueOnce({
        json: async () => ({
          code: 0,
          data: {
            user: {
              enterprise_email: 'derek@configreality.com',
              name: 'Derek',
              user_id: 'ou_user',
            },
          },
        }),
        ok: true,
      } as Response);

    const user = await config.getUserInfo?.({
      accessToken: 'token',
      raw: {
        code: 0,
        data: {
          access_token: 'token',
          union_id: 'on_test',
          user_id: 'ou_user',
        },
      },
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(user).toMatchObject({
      email: 'derek@configreality.com',
      id: 'on_test',
      name: 'Derek',
      user_id: 'ou_user',
    });
  });
});
