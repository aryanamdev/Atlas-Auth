import { createHash } from 'crypto';
import { db } from '#config/db.js';
import { oauthClients, authorizationCodes } from '#models/auth.model.js';
import { eq } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { ApiError } from '#utils/apiError.js';
import { verifyPassword } from '#utils/password.js';
import type { JwtPayload } from '#utils/jwt.js';
import { jwtUtils } from '#utils/jwt.js';

const AUTH_CODE_TTL_SECONDS = Number(process.env.AUTH_CODE_TTL_SECONDS || 600);

export const findClientById = async (clientId: string) => {
  const [client] = await db
    .select()
    .from(oauthClients)
    .where(eq(oauthClients.clientId, clientId));
  return client;
};

export const validateClientCredentials = async (
  clientId: string,
  clientSecret?: string
) => {
  const client = await findClientById(clientId);
  if (!client || !client.isActive) {
    throw new ApiError(401, 'Invalid OAuth client');
  }

  if (client.publicClient) {
    return client;
  }

  if (!clientSecret || !client.clientSecret) {
    throw new ApiError(401, 'Invalid OAuth client');
  }

  const secretMatches = await verifyPassword(client.clientSecret, clientSecret);
  if (!secretMatches) {
    throw new ApiError(401, 'Invalid OAuth client');
  }

  return client;
};

export const createAuthorizationCode = async (
  userId: number,
  clientId: number,
  redirectUri: string,
  scope: string,
  codeChallenge: string,
  codeChallengeMethod: string,
  nonce?: string
) => {
  const code = uuidv4();
  const expiresAt = new Date(Date.now() + AUTH_CODE_TTL_SECONDS * 1000);

  await db.insert(authorizationCodes).values({
    code,
    userId,
    clientId,
    redirectUri,
    scope,
    codeChallenge,
    codeChallengeMethod,
    nonce,
    expiresAt,
  });

  return code;
};

export const exchangeAuthorizationCode = async (
  code: string,
  clientId: number,
  redirectUri: string,
  codeVerifier: string
) => {
  const [stored] = await db
    .select()
    .from(authorizationCodes)
    .where(eq(authorizationCodes.code, code));

  if (!stored || stored.clientId !== clientId || stored.redirectUri !== redirectUri) {
    throw new ApiError(400, 'Invalid authorization code');
  }

  if (stored.expiresAt < new Date()) {
    throw new ApiError(400, 'Authorization code expired');
  }

  if (stored.codeChallengeMethod !== 'S256') {
    throw new ApiError(400, 'Unsupported PKCE challenge method');
  }

  const challenge = createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  if (challenge !== stored.codeChallenge) {
    throw new ApiError(400, 'PKCE verification failed');
  }

  await db.delete(authorizationCodes).where(eq(authorizationCodes.code, code));

  return stored;
};

export const createOidcIdToken = (
  user: { id: number; email: string; name: string; role: string; emailVerified: boolean },
  clientId: string,
  nonce?: string
): string => {
  const payload: JwtPayload & {
    aud: string;
    name: string;
    email: string;
    nonce?: string;
  } = {
    sub: String(user.id),
    role: user.role as JwtPayload['role'],
    emailVerified: user.emailVerified,
    aud: clientId,
    name: user.name,
    email: user.email,
    ...(nonce ? { nonce } : {}),
  };

  return jwtUtils.signIdToken(payload);
};
