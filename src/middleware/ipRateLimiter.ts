import { Request, Response, NextFunction } from 'express';
import { ApiError } from '#utils/apiError.js';

const ipBuckets = new Map<string, { tokens: number; lastRefill: number }>();
const RATE_LIMIT = Number(process.env.IP_RATE_LIMIT || 120);
const REFILL_INTERVAL_MS = Number(process.env.IP_RATE_LIMIT_WINDOW_MS || 60_000);

export const ipRateLimiter = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const key = req.ip || req.headers['x-forwarded-for']?.toString() || 'unknown';
  const now = Date.now();
  const bucket = ipBuckets.get(key) ?? { tokens: RATE_LIMIT, lastRefill: now };

  const elapsed = now - bucket.lastRefill;
  const refillCount = Math.floor(elapsed / REFILL_INTERVAL_MS);
  if (refillCount > 0) {
    bucket.tokens = Math.min(RATE_LIMIT, bucket.tokens + refillCount);
    bucket.lastRefill = now;
  }

  if (bucket.tokens <= 0) {
    ipBuckets.set(key, bucket);
    throw new ApiError(429, 'Too many requests from this IP');
  }

  bucket.tokens -= 1;
  ipBuckets.set(key, bucket);
  next();
};
