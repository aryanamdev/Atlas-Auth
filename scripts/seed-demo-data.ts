import dotenv from 'dotenv';
import { hashPassword } from '#utils/password.js';
import { db } from '#config/db.js';
import { users } from '#models/users.model.js';
import { oauthClients } from '#models/auth.model.js';
import { eq } from 'drizzle-orm';

dotenv.config();

const demoEmail = process.env.DEMO_USER_EMAIL ?? 'demo@example.com';
const demoPassword = process.env.DEMO_USER_PASSWORD ?? 'DemoPass123!';
const demoName = process.env.DEMO_USER_NAME ?? 'Demo User';
const demoClientId = process.env.DEMO_CLIENT_ID ?? 'demo-client';
const demoRedirectUri = process.env.DEMO_REDIRECT_URI ?? 'http://localhost:4000/callback';

async function seedDemoUser() {
  const [existingUser] = await db
    .select()
    .from(users)
    .where(eq(users.email, demoEmail));

  const hashedPassword = await hashPassword(demoPassword);

  if (existingUser) {
    await db
      .update(users)
      .set({
        password: hashedPassword,
        emailVerified: true,
        updatedAt: new Date(),
      })
      .where(eq(users.id, existingUser.id));

    console.log(`Updated existing demo user: ${demoEmail}`);
    return;
  }

  await db.insert(users).values({
    name: demoName,
    email: demoEmail,
    password: hashedPassword,
    role: 'user',
    emailVerified: true,
  });

  console.log(`Created demo user: ${demoEmail}`);
}

async function seedDemoClient() {
  const [existingClient] = await db
    .select()
    .from(oauthClients)
    .where(eq(oauthClients.clientId, demoClientId));

  if (existingClient) {
    await db
      .update(oauthClients)
      .set({
        redirectUri: demoRedirectUri,
        publicClient: true,
        isActive: true,
      })
      .where(eq(oauthClients.id, existingClient.id));

    console.log(`Updated existing demo OAuth client: ${demoClientId}`);
    return;
  }

  await db.insert(oauthClients).values({
    clientId: demoClientId,
    redirectUri: demoRedirectUri,
    name: 'Demo OAuth Client',
    publicClient: true,
    isActive: true,
  });

  console.log(`Created demo OAuth client: ${demoClientId}`);
}

async function main() {
  try {
    await seedDemoUser();
    await seedDemoClient();
    console.log('Demo seed complete. You can run `npm run demo` next.');
  } catch (error) {
    console.error('Demo seed failed:', error instanceof Error ? error.message : error);
    process.exit(1);
  }
}

main();
