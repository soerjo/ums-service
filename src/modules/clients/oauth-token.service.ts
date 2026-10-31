import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { createHash } from 'node:crypto';
import { PrismaService } from '../../prisma/prisma.service.js';
import { AuthService } from '../auth/auth.service.js';
import { ClientRateLimiterService } from './client-rate-limiter.service.js';
import { verifySecretHash } from './client-secrets.util.js';
import { M2M_TOKEN_TTL_SECONDS } from './clients.constants.js';
import { ClientsRepository } from './clients.repository.js';
import { ClientCredentialsDto } from './dto/client-credentials.dto.js';
import { TokenRequestDto } from './dto/token-request.dto.js';
import {
  generateOpaqueToken,
  sha256Hex,
} from '../../common/utils/hash.util.js';

export interface ClientCredentialsTokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
}

export interface AuthCodeTokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

@Injectable()
export class OauthTokenService {
  constructor(
    private readonly clientsRepository: ClientsRepository,
    private readonly clientRateLimiter: ClientRateLimiterService,
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly authService: AuthService,
  ) {}

  async issueClientCredentialsToken(
    dto: ClientCredentialsDto,
  ): Promise<ClientCredentialsTokenResponse> {
    const client = await this.clientsRepository.findByClientId(dto.client_id);
    if (!client || !client.active) {
      throw new UnauthorizedException('invalid_client');
    }

    if (!verifySecretHash(dto.client_secret, client.clientSecretHash)) {
      throw new UnauthorizedException('invalid_client');
    }

    const rateLimit = this.clientRateLimiter.consume(
      client.clientId,
      client.rateLimitPerMinute,
    );
    if (!rateLimit.allowed) {
      throw new HttpException(
        { error: 'too_many_requests', retry_after_ms: rateLimit.retryAfterMs },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    await this.clientsRepository.touchLastUsed(client.id, new Date());

    const accessToken = this.jwtService.sign({
      sub: client.clientId,
      azp: client.clientId,
      scopes: client.scopes,
    });

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: M2M_TOKEN_TTL_SECONDS,
      scope: client.scopes.join(' '),
    };
  }

  async createAuthorizationCode(params: {
    clientId: string;
    userId: string;
    redirectUri: string;
    codeChallenge?: string;
    scope?: string;
  }): Promise<string> {
    const rawCode = `code_${generateOpaqueToken(24)}`;
    const codeHash = sha256Hex(rawCode);
    const expiresAt = new Date(Date.now() + 60 * 1000); // 60s TTL

    await this.prisma.authorizationCode.create({
      data: {
        codeHash,
        clientId: params.clientId,
        userId: params.userId,
        redirectUri: params.redirectUri,
        codeChallenge: params.codeChallenge ?? null,
        scope: params.scope ?? null,
        expiresAt,
      },
    });

    return rawCode;
  }

  async exchangeAuthorizationCode(
    dto: TokenRequestDto,
  ): Promise<AuthCodeTokenResponse> {
    if (!dto.code) {
      throw new BadRequestException('Missing authorization code');
    }

    const codeHash = sha256Hex(dto.code);
    const record = await this.prisma.authorizationCode.findUnique({
      where: { codeHash },
    });

    if (!record || record.usedAt || record.expiresAt < new Date()) {
      throw new BadRequestException('Invalid or expired authorization code');
    }

    if (dto.redirect_uri && record.redirectUri !== dto.redirect_uri) {
      throw new BadRequestException('redirect_uri mismatch');
    }

    if (record.codeChallenge) {
      if (!dto.code_verifier) {
        throw new BadRequestException('Missing code_verifier for PKCE');
      }
      // S256 verification
      const computedChallenge = createHash('sha256')
        .update(dto.code_verifier)
        .digest('base64url');
      if (computedChallenge !== record.codeChallenge) {
        throw new BadRequestException('Invalid code_verifier');
      }
    }

    // Mark code used
    await this.prisma.authorizationCode.update({
      where: { id: record.id },
      data: { usedAt: new Date() },
    });

    const issued = await this.authService.issueTokensForUser(record.userId);

    const idToken = this.jwtService.sign({
      sub: issued.user.id,
      email: issued.user.email,
      name: issued.user.name,
      aud: record.clientId,
    });

    return {
      access_token: issued.accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: issued.refreshToken,
      id_token: idToken,
      scope: record.scope ?? 'openid profile email',
    };
  }

  async handleTokenRequest(
    dto: TokenRequestDto,
  ): Promise<ClientCredentialsTokenResponse | AuthCodeTokenResponse> {
    if (dto.grant_type === 'client_credentials') {
      return this.issueClientCredentialsToken({
        client_id: dto.client_id ?? '',
        client_secret: dto.client_secret ?? '',
      });
    }

    if (dto.grant_type === 'authorization_code') {
      return this.exchangeAuthorizationCode(dto);
    }

    throw new BadRequestException(`Unsupported grant_type: ${dto.grant_type}`);
  }
}
