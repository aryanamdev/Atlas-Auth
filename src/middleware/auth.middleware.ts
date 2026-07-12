import { Request, Response, NextFunction } from 'express';
import { db } from '#config/db.js';
import { users } from '#models/users.model.js';
import { eq } from 'drizzle-orm';
import { jwtUtils, type AccessTokenPayload, UserRole } from '#utils/jwt.js';
import { ApiError } from '#utils/apiError.js';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: number;
    role: UserRole;
    emailVerified: boolean;
  };
}

export const requireAuth = (allowedRoles: UserRole[] = [UserRole.USER]) => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      const authorization = req.headers.authorization;
      if (!authorization?.startsWith('Bearer ')) {
        throw new ApiError(401, 'Missing authorization header');
      }

      const token = authorization.replace('Bearer ', '').trim();
      const payload = jwtUtils.verifyAccessToken(token);

      const [user] = await db.select().from(users).where(eq(users.id, Number(payload.sub)));
      if (!user) {
        throw new ApiError(401, 'Unauthorized');
      }

      req.user = {
        id: user.id,
        role: user.role as UserRole,
        emailVerified: user.emailVerified,
      };

      if (!allowedRoles.includes(req.user.role)) {
        throw new ApiError(403, 'Forbidden');
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};
