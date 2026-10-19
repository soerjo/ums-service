import { Body, Controller, HttpCode, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { CurrentUser } from '../../common/decorators/current-user.decorator.js';
import { Public } from '../../common/decorators/public.decorator.js';
import { MfaService } from './mfa.service.js';
import { AuthService } from '../auth/auth.service.js';
import {
  MfaConfirmDto,
  MfaDisableDto,
  MfaChallengeDto,
} from './dto/mfa.dto.js';

@Controller('mfa')
export class MfaController {
  constructor(
    private readonly mfaService: MfaService,
    private readonly authService: AuthService,
  ) {}

  @Post('enroll')
  @HttpCode(200)
  async enroll(@CurrentUser('id') userId: string) {
    return this.mfaService.enroll(userId);
  }

  @Post('confirm')
  @HttpCode(200)
  async confirm(@CurrentUser('id') userId: string, @Body() dto: MfaConfirmDto) {
    return this.mfaService.confirm(userId, dto.code);
  }

  @Post('disable')
  @HttpCode(200)
  async disable(@CurrentUser('id') userId: string, @Body() dto: MfaDisableDto) {
    await this.mfaService.disable(userId, dto.password);
    return { disabled: true };
  }

  @Post('challenge')
  @HttpCode(200)
  @Public()
  async challenge(
    @Body() dto: MfaChallengeDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { userId } = await this.mfaService.verifyChallenge(
      dto.challengeId,
      dto.code,
    );
    const ip = req.ip;
    const userAgent = req.get('user-agent') ?? undefined;
    const tokens = await this.authService.issueTokensForUser(userId, {
      ip,
      userAgent,
    });
    res.cookie('ums_refresh_token', tokens.refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      path: '/api/auth',
    });
    return tokens;
  }
}
