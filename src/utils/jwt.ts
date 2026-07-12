import { createPublicKey, createPrivateKey, generateKeyPairSync } from 'crypto';
import jwt, { SignOptions } from 'jsonwebtoken';
import { logger } from '#config/logger.js';
import { ApiError } from '#utils/apiError.js';

const issuer = process.env.JWT_ISSUER || 'http://localhost:3000';
const audience = process.env.JWT_AUDIENCE || 'atlas-auth';
const keyId = process.env.JWT_KID || 'auth-server-key';
const privateKeyPem = process.env.JWT_PRIVATE_KEY?.replace(/\\n/g, '\n');
const publicKeyPem = process.env.JWT_PUBLIC_KEY?.replace(/\\n/g, '\n');

const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';
const EMAIL_VERIFICATION_EXPIRY = process.env.EMAIL_VERIFICATION_EXPIRY || '1d';
const PASSWORD_RESET_EXPIRY = process.env.PASSWORD_RESET_EXPIRY || '1h';

const loadKeyPair = () => {
  if (privateKeyPem && publicKeyPem) {
    return {
      privateKey: createPrivateKey({ key: privateKeyPem, format: 'pem' }),
      publicKey: createPublicKey({ key: publicKeyPem, format: 'pem' }),
    };
  }

  logger.warn(
    'JWT_PRIVATE_KEY or JWT_PUBLIC_KEY not found, generating temporary RSA key pair. Do not use in production.'
  );

  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });

  return {
    privateKey: createPrivateKey({ key: privateKey, format: 'pem' }),
    publicKey: createPublicKey({ key: publicKey, format: 'pem' }),
  };
};

const { privateKey, publicKey } = loadKeyPair();

const publicKeyJwk = {
  ...(publicKey.export({ format: 'jwk' }) as Record<string, string>),
  kid: keyId,
  alg: 'RS256',
  use: 'sig',
};

export const jwks = {
  keys: [publicKeyJwk],
};

export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
}

export type JwtPayload = {
  sub: string;
  role: UserRole;
  emailVerified: boolean;
};

export type RefreshTokenPayload = JwtPayload & {
  jti: string;
  fam: string;
  type: 'refresh';
};

export type AccessTokenPayload = JwtPayload & {
  type: 'access';
};

export type EmailVerificationPayload = {
  sub: string;
  email: string;
  type: 'email_verification';
};

export type PasswordResetPayload = {
  sub: string;
  email: string;
  type: 'password_reset';
};

const parseExpiry = (expiry: string): number => {
  const timeUnit = expiry.slice(-1);
  const timeValue = parseInt(expiry.slice(0, -1), 10);
  
  switch (timeUnit) {
    case 's': return timeValue; // seconds
    case 'm': return timeValue * 60; // minutes
    case 'h': return timeValue * 3600; // hours
    case 'd': return timeValue * 86400; // days
    default: throw new Error('Invalid expiry format');
  }
};

const signToken = <T extends object>(
  payload: T,
  expiresIn: string,
  type: string
): string => {
  try {
    const options: SignOptions = {
      algorithm: 'RS256',
      expiresIn: parseExpiry(expiresIn),
      issuer,
      audience,
      keyid: keyId,
    };
    return jwt.sign({ ...payload, type }, privateKey, options);
  } catch (error) {
    logger.error('Failed to sign token', error);
    throw new ApiError(500, 'Failed to sign token');
  }
};

const verifyToken = <T extends { type?: string }>(
  token: string,
  expectedType?: string
): T => {
  try {
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      issuer,
      audience,
    });
    if (typeof decoded === 'string') {
      throw new ApiError(401, 'Unauthorized');
    }
    const payload = decoded as T;
    if (expectedType && payload.type !== expectedType) {
      throw new ApiError(401, 'Unauthorized');
    }
    return payload;
  } catch (error) {
    logger.error('JWT verification failed', error);
    throw new ApiError(401, 'Unauthorized');
  }
};

export const jwtUtils = {
  signAccessToken: (payload: JwtPayload): string =>
    signToken({ ...payload }, ACCESS_TOKEN_EXPIRY, 'access'),

  signRefreshToken: (
    payload: JwtPayload,
    jti: string,
    familyId: string
  ): string =>
    signToken(
      { ...payload, jti, fam: familyId },
      REFRESH_TOKEN_EXPIRY,
      'refresh'
    ),

  signIdToken: (payload: object): string =>
    signToken(payload, ACCESS_TOKEN_EXPIRY, 'id_token'),

  signEmailVerificationToken: (
    payload: EmailVerificationPayload
  ): string => signToken(payload, EMAIL_VERIFICATION_EXPIRY, 'email_verification'),

  signPasswordResetToken: (
    payload: PasswordResetPayload
  ): string => signToken(payload, PASSWORD_RESET_EXPIRY, 'password_reset'),

  verifyAccessToken: (token: string): AccessTokenPayload =>
    verifyToken<AccessTokenPayload>(token, 'access'),

  verifyRefreshToken: (token: string): RefreshTokenPayload =>
    verifyToken<RefreshTokenPayload>(token, 'refresh'),

  verifyEmailVerificationToken: (
    token: string
  ): EmailVerificationPayload => verifyToken<EmailVerificationPayload>(token, 'email_verification'),

  verifyPasswordResetToken: (
    token: string
  ): PasswordResetPayload => verifyToken<PasswordResetPayload>(token, 'password_reset'),
};
