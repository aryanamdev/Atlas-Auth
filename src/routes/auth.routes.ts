import express from 'express';
import {
  login,
  logout,
  refreshAccessToken,
  register,
  verifyEmail,
  forgotPassword,
  resetPasswordHandler,
} from '#controllers/auth.controller.js';
import { validateCsrfToken } from '#middleware/csrf.middleware.js';

const router = express.Router({});

router.post('/register', register);
router.get('/verify-email', verifyEmail);
router.post('/login', login);
router.post('/refresh-token', validateCsrfToken, refreshAccessToken);
router.post('/logout', validateCsrfToken, logout);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPasswordHandler);

export default router;
