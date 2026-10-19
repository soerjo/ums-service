import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import request from 'supertest';
import { App } from 'supertest/types';
import { validate } from '../src/config/env.validation.js';
import { readFileSync } from 'node:fs';

// Opt-in only: requires a live database and RS256 key env. Run with
// `RUN_E2E=true bun run test:e2e`.
const RUN_E2E = process.env.RUN_E2E === 'true';
const describeE2e = RUN_E2E ? describe : describe.skip;

interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  user: { email: string };
}

describeE2e('Auth flow (e2e)', () => {
  let app: INestApplication<App>;
  const email = `e2e-${Date.now()}@example.com`;
  const password = 'SuperSecret123';

  beforeAll(async () => {
    // Imported lazily so a skipped run never evaluates AppModule (its
    // ConfigModule.forRoot validates env at import time).
    const { AppModule } = await import('./../src/app.module.js');

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, validate, load: [] }),
        AppModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api');
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('registers, logs in, refreshes (rotates) and logs out', async () => {
    const server = app.getHttpServer();

    await request(server)
      .post('/api/auth/register')
      .send({ email, password, name: 'E2E User' })
      .expect(201);

    const login = await request(server)
      .post('/api/auth/login')
      .send({ email, password })
      .expect(200);

    const loginBody = login.body as TokenResponse;
    expect(loginBody.accessToken).toBeDefined();
    expect(loginBody.refreshToken).toBeDefined();
    expect(loginBody.user.email).toBe(email);

    const refresh = await request(server)
      .post('/api/auth/refresh')
      .send({ refreshToken: loginBody.refreshToken })
      .expect(200);

    const refreshBody = refresh.body as TokenResponse;
    expect(refreshBody.refreshToken).toBeDefined();
    expect(refreshBody.refreshToken).not.toBe(loginBody.refreshToken);

    await request(server)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${refreshBody.accessToken}`)
      .send({ refreshToken: refreshBody.refreshToken })
      .expect(200);

    // Rotated-then-logged-out token must be rejected.
    await request(server)
      .post('/api/auth/refresh')
      .send({ refreshToken: refreshBody.refreshToken })
      .expect(401);
  });
});

// ---------------------------------------------------------------------------
// Epic 001 e2e: password reset + email verification flows.
// Requires a live database plus MAIL_TRANSPORT=log and MAIL_LOG_FILE set to a
// writable path: the dev log transport appends one JSON line per composed
// message there, so tests can capture the token-bearing link (documented dev
// behaviour — the link is only ever logged in 'log' mode, never in 'smtp').
// ---------------------------------------------------------------------------

interface MailLogEntry {
  event: string;
  to: string;
  subject: string;
  link: string;
}

interface AuthErrorBody {
  message: string;
}

function readMailLog(): MailLogEntry[] {
  const file = process.env.MAIL_LOG_FILE;
  if (!file) {
    throw new Error('MAIL_LOG_FILE env must be set for epic 001 e2e flows');
  }
  return readFileSync(file, 'utf8')
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as MailLogEntry)
    .filter((entry) => entry.event === 'mail.log-transport');
}

function lastTokenFor(
  entries: MailLogEntry[],
  email: string,
  subject: string,
): string {
  const matches = entries.filter(
    (entry) => entry.to === email && entry.subject === subject,
  );
  if (matches.length === 0) {
    throw new Error(`No mail log entry for ${email} (${subject})`);
  }
  const link = matches[matches.length - 1].link;
  const token = new URL(link).searchParams.get('token');
  if (!token) {
    throw new Error(`Link for ${email} (${subject}) carries no token`);
  }
  return token;
}

describeE2e('Epic 001 flows (e2e): password reset + email verification', () => {
  let app: INestApplication<App>;
  const resetEmail = `e2e-reset-${Date.now()}@example.com`;
  const oldPassword = 'OldPassword123';
  const newPassword = 'NewPassword456';
  const verifyEmail = `e2e-verify-${Date.now()}@example.com`;

  beforeAll(async () => {
    const { AppModule } = await import('./../src/app.module.js');

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, validate, load: [] }),
        AppModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api');
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('password reset: anti-enumeration, token from log, single use, sessions revoked', async () => {
    const server = app.getHttpServer();

    // Register + login so the user owns live sessions that must be revoked.
    await request(server)
      .post('/api/auth/register')
      .send({ email: resetEmail, password: oldPassword, name: 'E2E Reset' })
      .expect(201);
    const loginBefore = await request(server)
      .post('/api/auth/login')
      .send({ email: resetEmail, password: oldPassword })
      .expect(200);
    const oldRefreshToken = (loginBefore.body as TokenResponse).refreshToken;

    // Anti-enumeration: known and unknown emails answer identically.
    const unknownEmail = `e2e-unknown-${Date.now()}@example.com`;
    const knownStart = Date.now();
    const knownRes = await request(server)
      .post('/api/auth/forgot-password')
      .send({ email: resetEmail })
      .expect(200);
    const knownMs = Date.now() - knownStart;
    const unknownStart = Date.now();
    const unknownRes = await request(server)
      .post('/api/auth/forgot-password')
      .send({ email: unknownEmail })
      .expect(200);
    const unknownMs = Date.now() - unknownStart;
    expect(knownRes.body).toEqual(unknownRes.body);
    // Timing equalization: generous bounds so CI jitter cannot flake the run.
    expect(Math.max(knownMs, unknownMs)).toBeLessThan(5000);
    expect(Math.abs(knownMs - unknownMs)).toBeLessThan(3000);

    // Token comes from the dev mail log (documented dev behaviour).
    const resetToken = lastTokenFor(
      readMailLog(),
      resetEmail,
      'Reset your password',
    );

    // Reset succeeds with the fresh token.
    await request(server)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, password: newPassword })
      .expect(200);

    // Login with the NEW password works.
    const loginAfter = await request(server)
      .post('/api/auth/login')
      .send({ email: resetEmail, password: newPassword })
      .expect(200);
    expect((loginAfter.body as TokenResponse).accessToken).toBeDefined();

    // Login with the OLD password fails.
    await request(server)
      .post('/api/auth/login')
      .send({ email: resetEmail, password: oldPassword })
      .expect(401);

    // Old sessions are revoked: the pre-reset refresh token is rejected.
    await request(server)
      .post('/api/auth/refresh')
      .send({ refreshToken: oldRefreshToken })
      .expect(401);

    // Single use: reuse fails with the same message as an invalid token.
    const reuseRes = await request(server)
      .post('/api/auth/reset-password')
      .send({ token: resetToken, password: newPassword })
      .expect(400);
    const bogusRes = await request(server)
      .post('/api/auth/reset-password')
      .send({
        token:
          '0000000000000000000000000000000000000000000000000000000000000000',
        password: newPassword,
      })
      .expect(400);
    expect((reuseRes.body as AuthErrorBody).message).toBe(
      (bogusRes.body as AuthErrorBody).message,
    );
  });

  it('email verification: resend issues token, verify fills the flag, token single use', async () => {
    const server = app.getHttpServer();

    await request(server)
      .post('/api/auth/register')
      .send({
        email: verifyEmail,
        password: 'VerifyPass123',
        name: 'E2E Verify',
      })
      .expect(201);

    // Resend-verification for a registered, unverified email issues a token.
    const resKnown = await request(server)
      .post('/api/auth/resend-verification')
      .send({ email: verifyEmail })
      .expect(200);

    // Anti-enumeration: unknown email answers identically.
    const unknownEmail = `e2e-unknown-verify-${Date.now()}@example.com`;
    const resUnknown = await request(server)
      .post('/api/auth/resend-verification')
      .send({ email: unknownEmail })
      .expect(200);
    expect(resKnown.body).toEqual(resUnknown.body);

    const verifyToken = lastTokenFor(
      readMailLog(),
      verifyEmail,
      'Verify your email',
    );

    // Verify succeeds once.
    await request(server)
      .post('/api/auth/verify-email')
      .send({ token: verifyToken })
      .expect(200);

    // Same token again: rejected with the shared error message.
    const reuseVerify = await request(server)
      .post('/api/auth/verify-email')
      .send({ token: verifyToken })
      .expect(400);
    const bogusVerify = await request(server)
      .post('/api/auth/verify-email')
      .send({ token: 'definitely-not-a-real-token' })
      .expect(400);
    expect((reuseVerify.body as AuthErrorBody).message).toBe(
      (bogusVerify.body as AuthErrorBody).message,
    );

    // Verified email: resend-verification stays neutral 200 and no longer
    // issues a new token (no additional mail log entry for this address).
    const entriesBefore = readMailLog().filter(
      (entry) => entry.to === verifyEmail,
    ).length;
    await request(server)
      .post('/api/auth/resend-verification')
      .send({ email: verifyEmail })
      .expect(200);
    const entriesAfter = readMailLog().filter(
      (entry) => entry.to === verifyEmail,
    ).length;
    expect(entriesAfter).toBe(entriesBefore);
  });
});
