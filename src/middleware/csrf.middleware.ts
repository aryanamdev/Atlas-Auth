import { Request, Response, NextFunction } from 'express';
import { ApiError } from '#utils/apiError.js';

export const validateCsrfToken = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const cookieToken = req.cookies?.csrfToken;
  const headerToken = req.header('x-csrf-token');

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    throw new ApiError(403, 'CSRF token validation failed');
  }

  next();
};
