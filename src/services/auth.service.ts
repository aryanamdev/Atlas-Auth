import { db } from '#config/db.js';
import { users } from '#models/users.model.js';
import { eq } from 'drizzle-orm';
import { hashPassword, verifyPassword } from '#utils/password.js';
import { sendEmailVerification, sendPasswordReset } from '#services/email.service.js';
import { jwtUtils, type JwtPayload } from '#utils/jwt.js';
import { ApiError } from '#utils/apiError.js';

const MAX_FAILED_LOGIN_ATTEMPTS = Number(
  process.env.MAX_FAILED_LOGIN_ATTEMPTS || 5
);
const BACKOFF_MINUTES = Number(process.env.LOCKOUT_BACKOFF_MINUTES || 5);

export const findUserByEmail = async (email: string) => {
  const [user] = await db.select().from(users).where(eq(users.email, email));
  return user;
};

export const findUserById = async (id: number) => {
  const [user] = await db.select().from(users).where(eq(users.id, id));
  return user;
};

export const registerUser = async (
  name: string,
  email: string,
  password: string,
  role: string
) => {
  const existing = await findUserByEmail(email);
  if (existing) {
    throw new ApiError(409, 'User with this email already exists');
  }

  const hashedPassword = await hashPassword(password);
  const [created] = await db
    .insert(users)
    .values({
      name,
      email,
      password: hashedPassword,
      role,
    })
    .returning();

  const emailVerificationToken = jwtUtils.signEmailVerificationToken({
    sub: String(created.id),
    email: created.email,
    type: 'email_verification',
  });

  await sendEmailVerification(created.email, emailVerificationToken);

  return created;
};

export const verifyEmailToken = async (token: string) => {
  const payload = jwtUtils.verifyEmailVerificationToken(token);
  const userId = Number(payload.sub);
  const [user] = await db.select().from(users).where(eq(users.id, userId));

  if (!user) {
    throw new ApiError(404, 'User not found');
  }

  if (!user.emailVerified) {
    const [updated] = await db
      .update(users)
      .set({ emailVerified: true, updatedAt: new Date() })
      .where(eq(users.id, userId))
      .returning();
    return updated;
  }

  return user;
};

export const validateLogin = async (email: string, password: string) => {
  const user = await findUserByEmail(email);
  if (!user) {
    throw new ApiError(400, 'Invalid credentials');
  }

  if (user.lockoutUntil && user.lockoutUntil > new Date()) {
    throw new ApiError(
      429,
      'Account temporarily locked. Please wait before trying again.'
    );
  }

  const isValid = await verifyPassword(user.password, password);
  if (!isValid) {
    await incrementFailedAttempts(user.id, user.failedLoginAttempts || 0);
    throw new ApiError(400, 'Invalid credentials');
  }

  if (!user.emailVerified) {
    throw new ApiError(403, 'Please verify your email before logging in');
  }

  await resetLoginAttempts(user.id);
  return user;
};

export const incrementFailedAttempts = async (
  userId: number,
  failedAttempts: number
) => {
  const attempts = failedAttempts + 1;
  const lockoutUntil =
    attempts >= MAX_FAILED_LOGIN_ATTEMPTS
      ? new Date(Date.now() + BACKOFF_MINUTES * 60 * 1000 * attempts)
      : undefined;

  await db
    .update(users)
    .set({
      failedLoginAttempts: attempts,
      lockoutUntil,
      updatedAt: new Date(),
    })
    .where(eq(users.id, userId));
};

export const resetLoginAttempts = async (userId: number) => {
  await db
    .update(users)
    .set({
      failedLoginAttempts: 0,
      lockoutUntil: null,
      updatedAt: new Date(),
    })
    .where(eq(users.id, userId));
};

export const requestPasswordReset = async (email: string) => {
  const user = await findUserByEmail(email);
  if (!user) {
    return null;
  }

  const resetToken = jwtUtils.signPasswordResetToken({
    sub: String(user.id),
    email: user.email,
    type: 'password_reset'
  });

  await db
    .update(users)
    .set({
      passwordResetToken: resetToken,
      passwordResetExpiresAt: new Date(Date.now() + 60 * 60 * 1000),
      updatedAt: new Date(),
    })
    .where(eq(users.id, user.id));

  await sendPasswordReset(user.email, resetToken);
  return user;
};

export const resetPassword = async (token: string, password: string) => {
  const payload = jwtUtils.verifyPasswordResetToken(token);
  const userId = Number(payload.sub);
  const [user] = await db.select().from(users).where(eq(users.id, userId));

  if (!user) {
    throw new ApiError(404, 'User not found');
  }

  if (user.passwordResetToken !== token || !user.passwordResetExpiresAt) {
    throw new ApiError(400, 'Reset token is invalid or expired');
  }

  if (user.passwordResetExpiresAt < new Date()) {
    throw new ApiError(400, 'Reset token is invalid or expired');
  }

  const hashedPassword = await hashPassword(password);
  const [updated] = await db
    .update(users)
    .set({
      password: hashedPassword,
      passwordResetToken: null,
      passwordResetExpiresAt: null,
      updatedAt: new Date(),
    })
    .where(eq(users.id, userId))
    .returning();

  return updated;
};

export const buildAccessTokenPayload = (user: {
  id: number;
  role: string;
  emailVerified: boolean;
}) => ({
  sub: String(user.id),
  role: user.role as JwtPayload['role'],
  emailVerified: user.emailVerified,
});
