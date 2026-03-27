import { afterEach, describe, expect, it, vi } from 'vitest';

import provider from './feishu';

vi.mock('@/envs/auth', () => ({
  authEnv: {
    AUTH_FEISHU_APP_ID: undefined as string | undefined,
    AUTH_FEISHU_APP_SECRET: undefined as string | undefined,
  },
}));

describe('feishu provider', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('prefers the real email from the token payload when user_info omits email fields', async () => {
    const config = provider.build({
      AUTH_FEISHU_APP_ID: 'app-id',
      AUTH_FEISHU_APP_SECRET: 'app-secret',
    });

    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue({
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

    expect(fetchMock).toHaveBeenCalledOnce();
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
});
