import { logger } from '#config/logger.js';
import config from '#config/config.js';

export const sendEmailVerification = async (
  email: string,
  token: string
): Promise<void> => {
  const baseUrl = config.appBaseUrl;
  const verificationUrl = `${baseUrl}/api/v1/auth/verify-email?token=${encodeURIComponent(
    token
  )}`;

  logger.info(
    `Email verification link for ${email}: ${verificationUrl} (send this via your email provider in production)`
  );
};

export const sendPasswordReset = async (
  email: string,
  token: string
): Promise<void> => {
  const baseUrl = config.appBaseUrl;
  const resetUrl = `${baseUrl}/api/v1/auth/reset-password?token=${encodeURIComponent(
    token
  )}`;

  logger.info(
    `Password reset link for ${email}: ${resetUrl} (send this via your email provider in production)`
  );
};
