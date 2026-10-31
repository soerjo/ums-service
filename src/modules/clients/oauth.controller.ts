import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { Public } from '../../common/decorators/public.decorator.js';
import { AuthorizeQueryDto } from './dto/authorize-query.dto.js';
import { TokenRequestDto } from './dto/token-request.dto.js';
import { OauthTokenService } from './oauth-token.service.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import type { AuthUser } from '../../common/interfaces/auth-user.interface.js';

@ApiTags('OAuth')
@Controller('oauth')
export class OauthController {
  constructor(
    private readonly oauthTokenService: OauthTokenService,
    private readonly prisma: PrismaService,
  ) {}

  @Public()
  @Get('authorize')
  @ApiOperation({
    summary: 'OAuth2/OIDC authorize endpoint (Authorization Code flow)',
  })
  async authorize(
    @Query() query: AuthorizeQueryDto,
    @Req() req: Request & { user?: AuthUser },
    @Res() res: Response,
  ) {
    if (query.response_type !== 'code') {
      throw new BadRequestException('Only response_type=code is supported');
    }

    // Verify client/domain exists
    const client = await this.prisma.apiClient
      .findUnique({
        where: { clientId: query.client_id },
      })
      .catch(() => null);

    const domain = !client
      ? await this.prisma.domain
          .findFirst({
            where: {
              OR: [{ id: query.client_id }, { origin: query.redirect_uri }],
            },
          })
          .catch(() => null)
      : null;

    if (!client && !domain) {
      throw new BadRequestException('Unknown client_id');
    }

    // If user is already authenticated in UMS session, issue authorization code immediately
    const user = req.user;
    if (user) {
      const code = await this.oauthTokenService.createAuthorizationCode({
        clientId: query.client_id,
        userId: user.id,
        redirectUri: query.redirect_uri,
        codeChallenge: query.code_challenge,
        scope: query.scope,
      });

      const redirect = new URL(query.redirect_uri);
      redirect.searchParams.set('code', code);
      if (query.state) {
        redirect.searchParams.set('state', query.state);
      }
      return res.redirect(redirect.toString());
    }

    // Otherwise redirect to UMS Login page with return query
    const loginUrl = new URL('/login', 'http://localhost:3000');
    loginUrl.searchParams.set('return_to', req.originalUrl || req.url);
    loginUrl.searchParams.set('client_id', query.client_id);
    return res.redirect(loginUrl.toString());
  }

  @Public()
  @Throttle({ default: { limit: 60, ttl: 60_000 } })
  @Post('token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary:
      'OAuth2 token endpoint supporting client_credentials & authorization_code',
  })
  token(@Body() dto: TokenRequestDto) {
    return this.oauthTokenService.handleTokenRequest(dto);
  }
}
