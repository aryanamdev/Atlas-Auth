import { createHash, randomBytes } from 'node:crypto';
import { URL, URLSearchParams } from 'node:url';
import readline from 'node:readline';

const authServerBase = process.env.AUTH_SERVER_URL?.replace(/\/$/, '') ?? 'http://localhost:3000';
const clientId = process.env.DEMO_CLIENT_ID ?? 'demo-client';
const clientSecret = process.env.DEMO_CLIENT_SECRET;
const callbackPort = Number(process.env.DEMO_CLIENT_PORT ?? 4000);
const redirectUri = process.env.DEMO_REDIRECT_URI ?? `http://localhost:${callbackPort}/callback`;
const scope = process.env.DEMO_SCOPE ?? 'openid profile';
const loginUrl = new URL('/api/v1/auth/login', authServerBase).toString();
const authorizationUrl = new URL('/oauth/authorize', authServerBase).toString();
const tokenUrl = new URL('/oauth/token', authServerBase).toString();

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const ask = (question: string): Promise<string> =>
  new Promise(resolve => {
    rl.question(question, answer => resolve(answer.trim()));
  });

const base64Url = (buffer: Buffer) =>
  buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const codeVerifier = base64Url(randomBytes(64));
const codeChallenge = base64Url(
  createHash('sha256').update(codeVerifier).digest()
);
const state = base64Url(randomBytes(16));
const nonce = base64Url(randomBytes(16));

async function login(email: string, password: string) {
  const response = await fetch(loginUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  const json = await response.json();
  if (!response.ok) {
    throw new Error(
      `Login failed (${response.status}): ${json?.message ?? JSON.stringify(json)}`
    );
  }

  if (!json?.data?.tokens?.accessToken) {
    throw new Error('Login response did not include an access token');
  }

  return json.data.tokens.accessToken as string;
}

async function authorize(accessToken: string) {
  const url = new URL(authorizationUrl);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', scope);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('nonce', nonce);

  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
    redirect: 'manual',
  });

  if (response.status !== 302) {
    const text = await response.text();
    throw new Error(
      `Authorization request failed (${response.status}): ${text}`
    );
  }

  const location = response.headers.get('location');
  if (!location) {
    throw new Error('Authorization response did not include a redirect location');
  }

  const redirect = new URL(location, authServerBase);
  if (redirect.searchParams.get('state') !== state) {
    throw new Error('State mismatch from authorization response');
  }

  const code = redirect.searchParams.get('code');
  if (!code) {
    throw new Error('Authorization response did not include a code');
  }

  return code;
}

async function exchangeToken(code: string) {
  const params = new URLSearchParams();
  params.set('grant_type', 'authorization_code');
  params.set('client_id', clientId);
  params.set('redirect_uri', redirectUri);
  params.set('code', code);
  params.set('code_verifier', codeVerifier);
  if (clientSecret) {
    params.set('client_secret', clientSecret);
  }

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  const json = await response.json();
  if (!response.ok) {
    throw new Error(
      `Token exchange failed (${response.status}): ${json?.message ?? JSON.stringify(json)}`
    );
  }

  return json;
}

async function main() {
  try {
    console.log('Demo OAuth2 client');
    console.log(`Auth server: ${authServerBase}`);
    console.log(`Client ID: ${clientId}`);
    console.log(`Redirect URI: ${redirectUri}`);

    const email = process.env.DEMO_USER_EMAIL ?? (await ask('Email: '));
    const password = process.env.DEMO_USER_PASSWORD ?? (await ask('Password: '));

    const accessToken = await login(email, password);
    console.log('Logged in successfully. Starting authorization request...');

    const code = await authorize(accessToken);
    console.log(`Authorization code received: ${code}`);

    const tokenResponse = await exchangeToken(code);
    console.log('Token exchange completed. Received tokens:');
    console.log(JSON.stringify(tokenResponse, null, 2));
  } catch (error) {
    console.error('Demo client failed:', error instanceof Error ? error.message : error);
    process.exit(1);
  } finally {
    rl.close();
  }
}

main();
