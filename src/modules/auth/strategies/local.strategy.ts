import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import type { Request } from 'express';
import { AuthService } from '../auth.service.js';
import { AuditService } from '../../audit/audit.service.js';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(
    private authService: AuthService,
    private auditService: AuditService,
  ) {
    super({
      usernameField: 'email',
      passReqToCallback: true,
    });
  }

  async validate(req: Request, email: string, password: string) {
    const body = (req.body ?? {}) as { domain?: unknown };
    const rawDomain =
      req.headers['x-domain-id'] ||
      req.headers['x-domain-origin'] ||
      req.headers['origin'] ||
      body.domain;
    const domainIdentifier = (
      Array.isArray(rawDomain) ? rawDomain[0] : rawDomain
    ) as string | undefined;

    const user = await this.authService.validateUser(
      email,
      password,
      domainIdentifier,
    );
    if (!user) {
      await this.auditService.log({
        action: 'auth.login.failed',
        severity: 'warn',
        metadata: { email },
      });
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }
}
