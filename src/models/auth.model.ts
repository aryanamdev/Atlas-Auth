import {
  boolean,
  integer,
  pgTable,
  serial,
  text,
  timestamp,
  varchar,
} from 'drizzle-orm/pg-core';

export const oauthClients = pgTable('oauth_clients', {
  id: serial('id').primaryKey(),
  clientId: text('client_id').notNull().unique(),
  clientSecret: text('client_secret'),
  redirectUri: text('redirect_uri').notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  publicClient: boolean('public_client').default(false).notNull(),
  isActive: boolean('is_active').default(true).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export const authorizationCodes = pgTable('authorization_codes', {
  code: text('code').primaryKey(),
  userId: integer('user_id').notNull(),
  clientId: integer('client_id').notNull(),
  redirectUri: text('redirect_uri').notNull(),
  scope: text('scope').notNull().default('openid profile'),
  codeChallenge: text('code_challenge').notNull(),
  codeChallengeMethod: text('code_challenge_method').notNull().default('S256'),
  nonce: text('nonce'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  expiresAt: timestamp('expires_at').notNull(),
});

export const refreshTokens = pgTable('refresh_tokens', {
  id: serial('id').primaryKey(),
  jti: text('jti').notNull().unique(),
  familyId: text('family_id').notNull(),
  userId: integer('user_id').notNull(),
  revoked: boolean('revoked').default(false).notNull(),
  revokedAt: timestamp('revoked_at'),
  replacedBy: text('replaced_by'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  lastUsedAt: timestamp('last_used_at'),
  ip: text('ip'),
  userAgent: text('user_agent'),
});
