import express from 'express';
import { authorize, token, jwks } from '#controllers/oauth.controller.js';

const router = express.Router({});

router.get('/authorize', authorize);
router.post('/token', token);
router.get('/jwks', jwks);

export default router;
