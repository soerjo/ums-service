import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { UMS_ADMIN_ROLE } from '../auth/auth.constants.js';
import { Public } from '../../common/decorators/public.decorator.js';
import { FederationService } from './federation.service.js';
import { CreateIdentityProviderDto } from './dto/create-identity-provider.dto.js';
import { UpdateIdentityProviderDto } from './dto/update-identity-provider.dto.js';
import { ConfigService } from '@nestjs/config';
import { Roles } from '../../common/decorators/roles.decorator.js';
import { AuthService } from '../auth/auth.service.js';

@ApiTags('Federation')
@Controller('federation/idps')
export class FederationAdminController {
  constructor(private readonly federation: FederationService) {}

  @Get()
  @ApiOperation({ summary: 'List configured identity providers (no secrets)' })
  @ApiOkResponse({ description: 'List of IdPs' })
  list() {
    return this.federation.list();
  }

  @Post()
  @Roles(UMS_ADMIN_ROLE)
  @ApiOperation({ summary: 'Register an OIDC identity provider' })
  create(@Body() dto: CreateIdentityProviderDto) {
    return this.federation.create(dto);
  }

  @Patch(':id')
  @Roles(UMS_ADMIN_ROLE)
  @ApiOperation({ summary: 'Update an identity provider' })
  update(@Param('id') id: string, @Body() dto: UpdateIdentityProviderDto) {
    return this.federation.update(
      id,
      dto as unknown as Record<string, unknown>,
    );
  }

  @Delete(':id')
  @Roles(UMS_ADMIN_ROLE)
  @ApiOperation({ summary: 'Remove an identity provider' })
  remove(@Param('id') id: string) {
    return this.federation.remove(id);
  }
}

/** Public browser-facing routes live under /api/auth/oidc. */
@ApiTags('Federation')
@Controller('auth/oidc')
export class FederationBrowserController {
  constructor(
    private readonly federation: FederationService,
    private readonly authService: AuthService,
    private readonly config: ConfigService,
  ) {}

  @Public()
  @Get(':idpId/start')
  @ApiOperation({ summary: 'Begin OIDC login — redirects to the IdP' })
  async start(
    @Param('idpId') idpId: string,
    @Query('domain') domain: string,
    @Query('redirect_uri') redirectUri: string,
    @Res() res: Response,
  ) {
    const url = await this.federation.buildAuthorizationUrl(idpId, {
      domainId: domain,
      redirectUri,
    });
    return res.redirect(url);
  }

  @Public()
  @Get(':idpId/callback')
  @ApiOperation({ summary: 'OIDC callback — exchanges code, matches by email' })
  async callback(
    @Param('idpId') idpId: string,
    @Query('code') code: string,
    @Query('state') state: string,
    @Res() res: Response,
  ) {
    try {
      const idpResult = await this.federation.exchangeCallback(
        idpId,
        code,
        state,
      );
      const tokens = await this.authService.federatedLogin(
        idpResult.email,
        {
          ip: res.req.ip,
          userAgent: res.req.headers['user-agent'],
        },
        idpResult.domainId,
        { name: idpResult.name },
      );

      res.cookie('ums_refresh_token', tokens.refreshToken, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        path: '/api/auth',
      });

      if (idpResult.redirectUri) {
        const targetUrl = new URL(idpResult.redirectUri);
        targetUrl.searchParams.set('accessToken', tokens.accessToken);
        targetUrl.searchParams.set('refreshToken', tokens.refreshToken);
        return res.redirect(targetUrl.toString());
      }

      const webUrl = (this.config.get<string>('APP_WEB_URL') ?? '/').replace(
        /\/$/,
        '',
      );
      return res.redirect(`${webUrl}/dashboard`);
    } catch {
      const loginUrl = this.config.get<string>('APP_WEB_URL') ?? '/';
      return res.redirect(`${loginUrl}/login?oidc=failed`);
    }
  }
}
