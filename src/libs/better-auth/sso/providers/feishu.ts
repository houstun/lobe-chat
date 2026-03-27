import { authEnv } from '@/envs/auth';

import { type GenericProviderDefinition } from '../types';

const FEISHU_AUTHORIZATION_URL = 'https://accounts.feishu.cn/open-apis/authen/v1/authorize';
const FEISHU_CONTACT_USER_URL = 'https://open.feishu.cn/open-apis/contact/v3/users';
const FEISHU_TENANT_TOKEN_URL = 'https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal';
const FEISHU_TOKEN_URL = 'https://open.feishu.cn/open-apis/authen/v2/oauth/token';
const FEISHU_USERINFO_URL = 'https://open.feishu.cn/open-apis/authen/v1/user_info';

type FeishuUserProfile = {
  avatar_big?: string;
  avatar_middle?: string;
  avatar_thumb?: string;
  avatar_url?: string;
  email?: string;
  en_name?: string;
  enterprise_email?: string;
  name?: string;
  open_id?: string;
  tenant_key?: string;
  union_id?: string;
  user_id?: string;
};

type FeishuUserInfoResponse = {
  code?: number;
  data?: FeishuUserProfile;
  msg?: string;
};

type FeishuTokenPayload = {
  access_token?: string;
  avatar_big?: string;
  avatar_middle?: string;
  avatar_thumb?: string;
  avatar_url?: string;
  email?: string;
  en_name?: string;
  enterprise_email?: string;
  expires_in?: number;
  name?: string;
  open_id?: string;
  refresh_token?: string;
  scope?: string;
  tenant_key?: string;
  tokenType?: string;
  token_type?: string;
  union_id?: string;
  user_id?: string;
};

type FeishuTokenResponse = {
  code?: number;
  data?: FeishuTokenPayload;
  message?: string;
  msg?: string;
} & FeishuTokenPayload;

type FeishuContactUserResponse = {
  code?: number;
  data?: {
    user?: FeishuUserProfile;
  };
  msg?: string;
};

type FeishuTenantTokenResponse = {
  code?: number;
  expire?: number;
  msg?: string;
  tenant_access_token?: string;
};

const isFeishuProfile = (value: unknown): value is FeishuUserProfile => {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.union_id === 'string' ||
    typeof candidate.open_id === 'string' ||
    typeof candidate.avatar_url === 'string' ||
    typeof candidate.name === 'string'
  );
};

const parseScopes = (scope: string | undefined) =>
  scope ? scope.split(/[\s,]+/).filter(Boolean) : [];

const pickFeishuEmail = (...emails: Array<string | undefined>) =>
  emails.find((email): email is string => !!email?.trim());

const resolveFeishuUserIdentifier = (
  profile: FeishuUserProfile,
  tokenPayload?: FeishuTokenPayload,
): { type: 'open_id' | 'union_id' | 'user_id'; value: string } | null => {
  const userId = profile.user_id ?? tokenPayload?.user_id;
  if (userId) return { type: 'user_id', value: userId };

  const openId = profile.open_id ?? tokenPayload?.open_id;
  if (openId) return { type: 'open_id', value: openId };

  const unionId = profile.union_id ?? tokenPayload?.union_id;
  if (unionId) return { type: 'union_id', value: unionId };

  return null;
};

const getTenantAccessToken = async (clientId: string, clientSecret: string) => {
  const response = await fetch(FEISHU_TENANT_TOKEN_URL, {
    body: JSON.stringify({
      app_id: clientId,
      app_secret: clientSecret,
    }),
    cache: 'no-store',
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    method: 'POST',
  });

  if (!response.ok) return null;

  const payload = (await response.json()) as FeishuTenantTokenResponse;
  if (payload.code !== 0 || !payload.tenant_access_token) return null;

  return payload.tenant_access_token;
};

const getContactProfile = async (
  accessToken: string,
  identifier: { type: 'open_id' | 'union_id' | 'user_id'; value: string },
) => {
  const url = new URL(`${FEISHU_CONTACT_USER_URL}/${identifier.value}`);
  url.searchParams.set('user_id_type', identifier.type);

  const response = await fetch(url, {
    cache: 'no-store',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'content-type': 'application/json; charset=utf-8',
    },
  });

  if (!response.ok) return null;

  const payload = (await response.json()) as FeishuContactUserResponse;
  if (payload.code !== 0) return null;

  return payload.data?.user;
};

const provider: GenericProviderDefinition<{
  AUTH_FEISHU_APP_ID: string;
  AUTH_FEISHU_APP_SECRET: string;
}> = {
  build: (env) => {
    const clientId = env.AUTH_FEISHU_APP_ID;
    const clientSecret = env.AUTH_FEISHU_APP_SECRET;

    return {
      authorizationUrl: FEISHU_AUTHORIZATION_URL,
      authorizationUrlParams: {
        app_id: clientId,
        response_type: 'code',
        scope: 'contact:user.base:readonly contact:user.email:readonly',
      },
      clientId,
      clientSecret,
      /**
       * Exchange code directly with Feishu (no proxy needed).
       */
      getToken: async ({ code, redirectURI }) => {
        const tokenResponse = await fetch(FEISHU_TOKEN_URL, {
          body: JSON.stringify({
            client_id: clientId,
            client_secret: clientSecret,
            code,
            grant_type: 'authorization_code',
            redirect_uri: redirectURI,
          }),
          cache: 'no-store',
          headers: {
            'content-type': 'application/json; charset=utf-8',
          },
          method: 'POST',
        });

        const parsed = (await tokenResponse.json()) as FeishuTokenResponse;
        const payload = parsed.data ?? parsed;

        const hasErrorCode = typeof parsed.code === 'number' && parsed.code !== 0;
        const tokenMissing = !payload.access_token;

        if (!tokenResponse.ok || hasErrorCode || tokenMissing) {
          throw new Error(parsed.msg ?? parsed.message ?? 'Failed to fetch Feishu OAuth token');
        }

        return {
          accessToken: payload.access_token,
          accessTokenExpiresAt: payload.expires_in
            ? new Date(Date.now() + payload.expires_in * 1000)
            : undefined,
          expiresIn: payload.expires_in,
          raw: parsed,
          refreshToken: payload.refresh_token,
          scopes: parseScopes(payload.scope),
          tokenType: payload.token_type ?? payload.tokenType ?? 'Bearer',
        };
      },
      getUserInfo: async (tokens) => {
        if (!tokens.accessToken) return null;

        const tokenPayload = (tokens as { raw?: FeishuTokenResponse }).raw?.data;
        const tokenProfile = tokenPayload && isFeishuProfile(tokenPayload) ? tokenPayload : undefined;

        const response = await fetch(FEISHU_USERINFO_URL, {
          cache: 'no-store',
          headers: {
            Authorization: `Bearer ${tokens.accessToken}`,
          },
        });

        let profile: FeishuUserProfile | undefined = tokenProfile;

        if (response.ok) {
          const payload = (await response.json()) as unknown;
          const profileResponse = payload as FeishuUserInfoResponse;

          if (!profileResponse.code || profileResponse.code === 0) {
            profile = profileResponse.data ?? (isFeishuProfile(payload) ? payload : tokenProfile);
          }
        }

        if (!profile) return null;

        const unionId =
          profile.union_id ?? tokenPayload?.union_id ?? profile.open_id ?? tokenPayload?.open_id;
        if (!unionId) return null;

        const identifier = resolveFeishuUserIdentifier(profile, tokenPayload);
        let contactProfile: FeishuUserProfile | null = null;

        if (identifier) {
          contactProfile = await getContactProfile(tokens.accessToken, identifier);

          if (!pickFeishuEmail(contactProfile?.email, contactProfile?.enterprise_email)) {
            const tenantAccessToken = await getTenantAccessToken(clientId, clientSecret);
            if (tenantAccessToken) {
              contactProfile = (await getContactProfile(tenantAccessToken, identifier)) ?? contactProfile;
            }
          }
        }

        // Prefer the user's real email when Feishu returns it so domain allowlists
        // and existing account linking continue to work. Fall back to a synthetic
        // email only when the tenant doesn't expose email fields at all.
        const email =
          pickFeishuEmail(
            profile.email,
            profile.enterprise_email,
            contactProfile?.email,
            contactProfile?.enterprise_email,
            tokenPayload?.email,
            tokenPayload?.enterprise_email,
          ) ?? `${unionId}@feishu.sso`;

        const resolvedProfile = {
          ...profile,
          ...contactProfile,
        };

        return {
          ...resolvedProfile,
          email,
          emailVerified: false,
          id: unionId,
          image:
            resolvedProfile.avatar_url ??
            resolvedProfile.avatar_thumb ??
            resolvedProfile.avatar_middle ??
            resolvedProfile.avatar_big,
          name: resolvedProfile.name ?? resolvedProfile.en_name ?? unionId,
        };
      },
      pkce: false,
      providerId: 'feishu',
      responseMode: 'query',
      scopes: ['contact:user.base:readonly', 'contact:user.email:readonly'],
      tokenUrl: FEISHU_TOKEN_URL,
    };
  },

  checkEnvs: () => {
    return !!(authEnv.AUTH_FEISHU_APP_ID && authEnv.AUTH_FEISHU_APP_SECRET)
      ? {
          AUTH_FEISHU_APP_ID: authEnv.AUTH_FEISHU_APP_ID,
          AUTH_FEISHU_APP_SECRET: authEnv.AUTH_FEISHU_APP_SECRET,
        }
      : false;
  },
  id: 'feishu',
  type: 'generic',
};

export default provider;
