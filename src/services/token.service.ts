import { db } from '#config/db.js';
import { refreshTokens } from '#models/auth.model.js';
import { jwtUtils, type JwtPayload } from '#utils/jwt.js';
import { v4 as uuidv4 } from 'uuid';
import { ApiError } from '#utils/apiError.js';
import { eq } from 'drizzle-orm';

const REFRESH_TOKEN_TTL_SECONDS = Number(
  process.env.REFRESH_TOKEN_TTL_SECONDS || 7 * 24 * 60 * 60
);

const buildExpiry = (): Date =>
  new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000);

export const createRefreshToken = async (
  userPayload: JwtPayload,
  ip?: string,
  userAgent?: string
): Promise<string> => {
  const familyId = uuidv4();
  const jti = uuidv4();
  const refreshToken = jwtUtils.signRefreshToken(userPayload, jti, familyId);

  await db.insert(refreshTokens).values({
    jti,
    familyId,
    userId: Number(userPayload.sub),
    expiresAt: buildExpiry(),
    ip,
    userAgent,
  });

  return refreshToken;
};

export const rotateRefreshToken = async (
  existingJti: string,
  userPayload: JwtPayload,
  ip?: string,
  userAgent?: string
): Promise<string> => {
  const [existingToken] = await db
    .select()
    .from(refreshTokens)
    .where(eq(refreshTokens.jti, existingJti));

  if (!existingToken || existingToken.revoked) {
    if (existingToken?.familyId) {
      await revokeRefreshTokenFamily(existingToken.familyId);
    }
    throw new ApiError(401, 'Refresh token is invalid or revoked');
  }

  const newJti = uuidv4();
  const newRefreshToken = jwtUtils.signRefreshToken(
    userPayload,
    newJti,
    existingToken.familyId
  );

  // Note: no db.transaction() here — the neon-http driver this project uses
  // doesn't support transactions (it errors with "No transactions support in
  // neon-http driver"). These two writes run sequentially instead; the reuse
  // check above plus the unique jti constraint keep this safe in practice.
  await db
    .update(refreshTokens)
    .set({
      revoked: true,
      revokedAt: new Date(),
      replacedBy: newJti,
      lastUsedAt: new Date(),
    })
    .where(eq(refreshTokens.jti, existingJti));

  await db.insert(refreshTokens).values({
    jti: newJti,
    familyId: existingToken.familyId,
    userId: existingToken.userId,
    expiresAt: buildExpiry(),
    ip,
    userAgent,
  });

  return newRefreshToken;
};

export const revokeRefreshTokenFamily = async (
  familyId: string,
): Promise<void> => {
  await db
    .update(refreshTokens)
    .set({ revoked: true, revokedAt: new Date() })
    .where(eq(refreshTokens.familyId, familyId));
};

export const validateRefreshTokenRow = async (
  jti: string
): Promise<{
  familyId: string;
  userId: number;
}> => {
  const [tokenRow] = await db
    .select()
    .from(refreshTokens)
    .where(eq(refreshTokens.jti, jti));

  if (!tokenRow || tokenRow.revoked || tokenRow.expiresAt < new Date()) {
    if (tokenRow?.familyId) {
      await revokeRefreshTokenFamily(tokenRow.familyId);
    }
    throw new ApiError(401, 'Refresh token is invalid or expired');
  }

  return {
    familyId: tokenRow.familyId,
    userId: tokenRow.userId,
  };
};
