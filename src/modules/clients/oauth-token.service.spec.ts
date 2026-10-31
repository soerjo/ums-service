import { HttpException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ClientRateLimiterService } from './client-rate-limiter.service.js';
import { hashSecret } from './client-secrets.util.js';
import { ClientsRepository } from './clients.repository.js';
import { OauthTokenService } from './oauth-token.service.js';

describe('OauthTokenService', () => {
  const secret = 'raw-client-secret';
  const client = {
    id: 'db-1',
    name: 'billing-worker',
    clientId: 'svc_abc',
    clientSecretHash: hashSecret(secret),
    scopes: ['users:read'],
    rateLimitPerMinute: 2,
    lastUsedAt: null,
    active: true,
    createdAt: new Date(),
  };

  let service: OauthTokenService;
  let clientsRepository: {
    findByClientId: jest.Mock;
    touchLastUsed: jest.Mock;
  };
  let jwtService: { sign: jest.Mock };

  beforeEach(() => {
    clientsRepository = { findByClientId: jest.fn(), touchLastUsed: jest.fn() };
    jwtService = { sign: jest.fn().mockReturnValue('signed.jwt.token') };
    service = new OauthTokenService(
      clientsRepository as unknown as ClientsRepository,
      new ClientRateLimiterService(),
      jwtService as unknown as JwtService,
      {} as any,
      {} as any,
    );
  });

  it('issues a token carrying sub/azp/scopes and updates lastUsedAt', async () => {
    clientsRepository.findByClientId.mockResolvedValue(client);

    const result = await service.issueClientCredentialsToken({
      client_id: client.clientId,
      client_secret: secret,
    });

    expect(jwtService.sign).toHaveBeenCalledWith({
      sub: 'svc_abc',
      azp: 'svc_abc',
      scopes: ['users:read'],
    });
    expect(result).toEqual({
      access_token: 'signed.jwt.token',
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'users:read',
    });
    expect(clientsRepository.touchLastUsed).toHaveBeenCalledTimes(1);
  });

  describe('authorization_code flow', () => {
    it('creates authorization code and exchanges it for tokens', async () => {
      const mockPrisma = {
        authorizationCode: {
          create: jest.fn().mockResolvedValue({ id: 'code-1' }),
          findUnique: jest.fn().mockResolvedValue({
            id: 'code-1',
            clientId: 'client-1',
            userId: 'user-1',
            redirectUri: 'https://app.test/cb',
            codeChallenge: null,
            scope: 'openid',
            expiresAt: new Date(Date.now() + 60000),
            usedAt: null,
          }),
          update: jest.fn().mockResolvedValue({ id: 'code-1' }),
        },
      };

      const mockAuthService = {
        issueTokensForUser: jest.fn().mockResolvedValue({
          accessToken: 'user.access.token',
          refreshToken: 'user.refresh.token',
          user: { id: 'user-1', email: 'u@test.com', name: 'User' },
        }),
      };

      const oauthService = new OauthTokenService(
        clientsRepository as unknown as ClientsRepository,
        new ClientRateLimiterService(),
        jwtService as unknown as JwtService,
        mockPrisma as unknown as any,
        mockAuthService as unknown as any,
      );

      const code = await oauthService.createAuthorizationCode({
        clientId: 'client-1',
        userId: 'user-1',
        redirectUri: 'https://app.test/cb',
      });

      expect(code).toBeDefined();

      const tokens = (await oauthService.handleTokenRequest({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.test/cb',
      })) as unknown as Record<string, unknown>;

      expect(tokens.access_token).toBe('user.access.token');
      expect(tokens.refresh_token).toBe('user.refresh.token');
    });
  });

  it('rejects an inactive client', async () => {
    clientsRepository.findByClientId.mockResolvedValue({
      ...client,
      active: false,
    });
    await expect(
      service.issueClientCredentialsToken({
        client_id: client.clientId,
        client_secret: secret,
      }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects a wrong secret and does not consume the rate limit', async () => {
    clientsRepository.findByClientId.mockResolvedValue(client);

    await expect(
      service.issueClientCredentialsToken({
        client_id: client.clientId,
        client_secret: 'wrong',
      }),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    await service.issueClientCredentialsToken({
      client_id: client.clientId,
      client_secret: secret,
    });
    await service.issueClientCredentialsToken({
      client_id: client.clientId,
      client_secret: secret,
    });
  });

  it('rejects with 429 once the per-client limit is exhausted', async () => {
    clientsRepository.findByClientId.mockResolvedValue(client);

    await service.issueClientCredentialsToken({
      client_id: client.clientId,
      client_secret: secret,
    });
    await service.issueClientCredentialsToken({
      client_id: client.clientId,
      client_secret: secret,
    });

    await expect(
      service.issueClientCredentialsToken({
        client_id: client.clientId,
        client_secret: secret,
      }),
    ).rejects.toBeInstanceOf(HttpException);
  });
});
