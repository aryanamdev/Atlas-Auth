import { randomUUID } from 'crypto';
import { logger } from '#config/logger.js';
import { ApiError } from '#utils/apiError.js';
import { ApiResponse } from '#utils/apiResponse.js';
import { cookies } from '#utils/cookies.js';
import { formatValidationError } from '#utils/formatValidation.js';
import {
  loginSchema,
  registerSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from '#validations/auth.validations.js';
import type { NextFunction, Request, Response } from 'express';
import {
  registerUser,
  verifyEmailToken,
  validateLogin,
  findUserById,
  buildAccessTokenPayload,
  requestPasswordReset,
  resetPassword,
} from '#services/auth.service.js';
// import {
//   createRefreshToken,
//   rotateRefreshToken,
//   revokeRefreshTokenFamily,
//   validateRefreshTokenRow,
// } from '#services/token.service.ts';
import { jwtUtils } from '#utils/jwt.js';
import { createRefreshToken, revokeRefreshTokenFamily, rotateRefreshToken, validateRefreshTokenRow } from '#services/token.service.js';

const refreshCookieOptions = {
  path: '/api/v1/auth/refresh-token',
  maxAge: 7 * 24 * 60 * 60 * 1000,
};

const csrfCookieOptions = {
  path: '/api/v1/auth/refresh-token',
  maxAge: 7 * 24 * 60 * 60 * 1000,
  httpOnly: false,
};

const buildCsrfToken = () => randomUUID();

export const register = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const result = registerSchema.safeParse(req.body);
    if (!result.success) {
      throw new ApiError(400, formatValidationError(result.error));
    }

    const { email, name, role, password } = result.data;
    const created = await registerUser(name, email, password, role);

    logger.info('User registered successfully, verification email sent', {
      userId: created.id,
      email: created.email,
    });

    return res.status(201).json(
      new ApiResponse(201, 'User registered successfully. Please verify your email.', {
        user: {
          id: created.id,
          name: created.name,
          email: created.email,
          role: created.role,
          emailVerified: created.emailVerified,
        },
      })
    );
  } catch (error) {
    next(error);
  }
};

export const verifyEmail = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const token = req.query.token;
    if (!token || typeof token !== 'string') {
      throw new ApiError(400, 'Verification token is required');
    }

    const user = await verifyEmailToken(token);
    const jwtPayload = buildAccessTokenPayload(user);
    const accessToken = jwtUtils.signAccessToken(jwtPayload);
    const refreshToken = await createRefreshToken(jwtPayload, req.ip, req.get('User-Agent') ?? undefined);
    const csrfToken = buildCsrfToken();

    cookies.set(res, 'refreshToken', refreshToken, refreshCookieOptions);
    cookies.set(res, 'csrfToken', csrfToken, csrfCookieOptions);

    return res.status(200).json(
      new ApiResponse(200, 'Email verified successfully', {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          emailVerified: user.emailVerified,
        },
        tokens: { accessToken, csrfToken },
      })
    );
  } catch (error) {
    next(error);
  }
};

export const login = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
      throw new ApiError(400, formatValidationError(result.error));
    }

    const { email, password } = result.data;
    const user = await validateLogin(email, password);
    const jwtPayload = buildAccessTokenPayload(user);
    const accessToken = jwtUtils.signAccessToken(jwtPayload);
    const refreshToken = await createRefreshToken(jwtPayload, req.ip, req.get('User-Agent') ?? undefined);
    const csrfToken = buildCsrfToken();

    cookies.set(res, 'refreshToken', refreshToken, refreshCookieOptions);
    cookies.set(res, 'csrfToken', csrfToken, csrfCookieOptions);

    return res.status(200).json(
      new ApiResponse(200, 'Logged in successfully', {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          emailVerified: user.emailVerified,
        },
        tokens: { accessToken, csrfToken },
      })
    );
  } catch (error) {
    next(error);
  }
};

export const refreshAccessToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const tokenFromCookie = cookies.get(req, 'refreshToken');
    const refreshToken =
      tokenFromCookie || (req.body?.refreshToken as string | undefined);
    if (!refreshToken) {
      throw new ApiError(401, 'Refresh token missing');
    }

    const payload = jwtUtils.verifyRefreshToken(refreshToken);
    await validateRefreshTokenRow(payload.jti);

    const user = await findUserById(Number(payload.sub));
    if (!user) {
      throw new ApiError(401, 'Unauthorized');
    }

    const jwtPayload = buildAccessTokenPayload(user);
    const accessToken = jwtUtils.signAccessToken(jwtPayload);
    const newRefreshToken = await rotateRefreshToken(
      payload.jti,
      jwtPayload,
      req.ip,
      req.get('User-Agent') ?? undefined
    );
    const csrfToken = buildCsrfToken();

    cookies.set(res, 'refreshToken', newRefreshToken, refreshCookieOptions);
    cookies.set(res, 'csrfToken', csrfToken, csrfCookieOptions);

    return res.status(200).json(
      new ApiResponse(200, 'Token refreshed', {
        tokens: { accessToken, csrfToken },
      })
    );
  } catch (error) {
    next(error);
  }
};

export const logout = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const refreshToken = cookies.get(req, 'refreshToken');
    if (refreshToken) {
      const payload = jwtUtils.verifyRefreshToken(refreshToken);
      await revokeRefreshTokenFamily(payload.fam);
    }

    cookies.clear(res, 'refreshToken', refreshCookieOptions);
    cookies.clear(res, 'csrfToken', csrfCookieOptions);

    return res.status(200).json(new ApiResponse(200, 'Logged out successfully'));
  } catch (error) {
    next(error);
  }
};

export const forgotPassword = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const result = forgotPasswordSchema.safeParse(req.body);
    if (!result.success) {
      throw new ApiError(400, formatValidationError(result.error));
    }

    await requestPasswordReset(result.data.email);
    return res.status(200).json(
      new ApiResponse(200, 'If that account exists, a reset link has been sent.')
    );
  } catch (error) {
    next(error);
  }
};

export const resetPasswordHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const result = resetPasswordSchema.safeParse(req.body);
    if (!result.success) {
      throw new ApiError(400, formatValidationError(result.error));
    }

    await resetPassword(result.data.token, result.data.password);
    return res.status(200).json(
      new ApiResponse(200, 'Password reset successfully. You can now log in.')
    );
  } catch (error) {
    next(error);
  }
};
