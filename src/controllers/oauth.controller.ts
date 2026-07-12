import { Request, Response, NextFunction } from 'express';
import { findClientById, validateClientCredentials, createAuthorizationCode, exchangeAuthorizationCode, createOidcIdToken } from '#services/oauth.service.js';
import { findUserById } from '#services/auth.service.js';
import { createRefreshToken } from '#services/token.service.js';
import { ApiError } from '#utils/apiError.js';
import { jwtUtils, type UserRole, jwks as jwksData } from '#utils/jwt.js';
import { ApiResponse } from '#utils/apiResponse.js';

export const authorize = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const {
      response_type: responseType,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope = 'openid profile',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      nonce,
    } = req.query;

    if (responseType !== 'code') {
      throw new ApiError(400, 'Unsupported response_type');
    }

    if (!clientId || typeof clientId !== 'string') {
      throw new ApiError(400, 'Missing client_id');
    }

    if (!redirectUri || typeof redirectUri !== 'string') {
      throw new ApiError(400, 'Missing redirect_uri');
    }

    if (!codeChallenge || typeof codeChallenge !== 'string') {
      throw new ApiError(400, 'Missing PKCE code_challenge');
    }

    if (codeChallengeMethod !== 'S256') {
      throw new ApiError(400, 'Unsupported PKCE method');
    }

    const client = await findClientById(clientId);
    if (!client) {
      throw new ApiError(400, 'Invalid client_id');
    }

    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      throw new ApiError(401, 'Authorization required');
    }

    const accessToken = authHeader.replace('Bearer ', '').trim();
    const payload = jwtUtils.verifyAccessToken(accessToken);
    const user = await findUserById(Number(payload.sub));
    if (!user) {
      throw new ApiError(401, 'Unauthorized');
    }

    const code = await createAuthorizationCode(
      user.id,
      client.id,
      redirectUri,
      String(scope),
      codeChallenge,
      String(codeChallengeMethod),
      typeof nonce === 'string' ? nonce : undefined
    );

    const redirect = new URL(redirectUri);
    redirect.searchParams.set('code', code);
    if (state) {
      redirect.searchParams.set('state', String(state));
    }

    return res.redirect(302, redirect.toString());
  } catch (error) {
    next(error);
  }
};

export const token = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const grantType = req.body.grant_type;
    if (grantType !== 'authorization_code') {
      throw new ApiError(400, 'Unsupported grant_type');
    }

    const clientId = req.body.client_id || req.headers['x-client-id'];
    const clientSecret = req.body.client_secret || req.headers['x-client-secret'];
    const redirectUri = req.body.redirect_uri;
    const code = req.body.code;
    const codeVerifier = req.body.code_verifier;

    if (!clientId || !redirectUri || !code || !codeVerifier) {
      throw new ApiError(400, 'Missing token request parameters');
    }

    const client = await validateClientCredentials(String(clientId), String(clientSecret));
    const stored = await exchangeAuthorizationCode(
      String(code),
      client.id,
      String(redirectUri),
      String(codeVerifier)
    );

    const user = await findUserById(stored.userId);
    if (!user) {
      throw new ApiError(401, 'Unauthorized');
    }

    const accessTokenPayload = {
      sub: String(user.id),
      role: user.role as UserRole,
      emailVerified: user.emailVerified,
    };

    const accessToken = jwtUtils.signAccessToken(accessTokenPayload);
    const refreshToken = await createRefreshToken(
      accessTokenPayload,
      req.ip,
      req.get('User-Agent') ?? undefined
    );
    const idToken = createOidcIdToken(user, client.clientId, stored.nonce ?? undefined);

    res.status(200).json(
      new ApiResponse(200, 'Token issued', {
        access_token: accessToken,
        refresh_token: refreshToken,
        id_token: idToken,
        token_type: 'Bearer',
        expires_in: 900,
        scope: stored.scope,
      })
    );
  } catch (error) {
    next(error);
  }
};

export const jwks = async (_req: Request, res: Response) => {
  return res.status(200).json(jwksData);
};
