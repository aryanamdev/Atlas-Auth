import express from 'express';
import { logger } from '#config/logger.js';
import helmet from 'helmet';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRouter from '#routes/auth.routes.js';
import oauthRouter from '#routes/oauth.routes.js';
import { jwks } from '#utils/jwt.js';
import { ApiError } from '#utils/apiError.js';
import globalErrorHandler from '#middleware/errorHandler.js';
import { ApiResponse } from '#utils/apiResponse.js';
import { ipRateLimiter } from '#middleware/ipRateLimiter.js';

const app = express();

const corsOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map(origin => origin.trim());

app.use(helmet());
app.use(
  cors({
    origin: corsOrigins,
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  morgan('combined', {
    stream: {
      write: message => {
        logger.info(message.trim());
      },
    },
  })
);

app.get('/', (_req, res) => {
  res.json(new ApiResponse(200, 'Atlas Auth API running'));
});

app.get('/health', (_req, res) => {
  res.status(200).send('Ok');
});

app.get('/.well-known/jwks.json', (_req, res) => res.json(jwks));

app.use('/api/v1/auth', ipRateLimiter, authRouter);
app.use('/oauth', ipRateLimiter, oauthRouter);

app.use((req, _res, next) => {
  next(new ApiError(404, `Cannot find ${req.originalUrl}`));
});

app.use(globalErrorHandler);

export default app;
