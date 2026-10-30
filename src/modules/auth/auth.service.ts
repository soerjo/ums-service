import { forwardRef } from '@nestjs/common';
import {
  BadRequestException,
  Injectable,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'node:crypto';
import { $Enums } from '@prisma/client';
import type { User } from '@prisma/client';
import { UsersRepository } from '../users/users.repository.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import { parseDurationToSeconds } from '../../common/utils/token-expiry.util.js';
import {
  hashPassword,
  verifyPassword,
} from '../../common/utils/password.util.js';
import {
  generateOpaqueToken,
  sha256Hex,
} from '../../common/utils/hash.util.js';
import { JWT_AZP } from './auth.constants.js';
import { AuthTokensRepository } from './auth-tokens.repository.js';
import type { MailSender } from '../mail/mail.types.js';
import { Inject } from '@nestjs/common';
import type { AuthUser } from '../../common/interfaces/auth-user.interface.js';
import { WebhookDispatcherService } from '../clients/webhook-dispatcher.service.js';
import type { RegisterDto } from './dto/register.dto.js';
import { AuditService } from '../audit/audit.service.js';
import { SecurityPoliciesService } from '../security-policies/security-policies.service.js';
import { OutboxService } from '../outbox/outbox.service.js';
import { PasswordPolicyService } from './password-policy.service.js';
import { AccountLockoutService } from './account-lockout.service.js';
import { UMS_TOPICS } from '../../events/ums.events.js';

export interface RequestMeta {
  userAgent?: string | null;
  ip?: string | null;
}

export interface IssuedTokens {
  accessToken: string;
  refreshToken: string;
  user: AuthUser;
}

export interface PublicUser {
  id: string;
  email: string;
  name: string | null;
  status: $Enums.UserStatus;
  emailVerifiedAt: Date | null;
  createdAt: Date;
}

@Injectable()
export class AuthService {
  constructor(
    private usersRepository: UsersRepository,
    private jwtService: JwtService,
    private configService: ConfigService,
    private prisma: PrismaService,
    private authTokensRepository: AuthTokensRepository,
    @Inject('MailSender') private mailSender: MailSender,
    private auditService: AuditService,
    @Inject(forwardRef(() => WebhookDispatcherService))
    private readonly webhookDispatcherService: WebhookDispatcherService,
    private readonly securityPoliciesService: SecurityPoliciesService,
    private readonly outboxService: OutboxService,
    private readonly passwordPolicyService: PasswordPolicyService,
    private readonly accountLockoutService: AccountLockoutService,
  ) {}

  public get accessTokenTtlSeconds(): number {
    const raw = this.configService.get<string>('JWT_ACCESS_EXPIRATION');
    return parseDurationToSeconds(raw ?? '15m');
  }

  public get refreshTokenTtlSeconds(): number {
    const raw = this.configService.get<string>('JWT_REFRESH_EXPIRATION');
    return parseDurationToSeconds(raw ?? '7d');
  }

  private async loadRoles(userId: string): Promise<string[]> {
    const rows = await this.prisma.userRole.findMany({
      where: { userId },
      select: { role: { select: { name: true } } },
    });
    return rows.map((row) => row.role.name);
  }

  private async loadOrgs(userId: string): Promise<string[]> {
    const rows = await this.prisma.orgMember.findMany({
      where: { userId },
      select: { organization: { select: { name: true } } },
    });
    return rows.map((row) => row.organization.name);
  }

  private async loadPerms(userId: string): Promise<string[]> {
    const rows = await this.prisma.userRole.findMany({
      where: { userId },
      select: {
        role: {
          select: {
            rolePermissions: {
              select: {
                permission: {
                  select: { name: true },
                },
              },
            },
          },
        },
      },
    });

    const permSet = new Set<string>();
    for (const ur of rows) {
      for (const rp of ur.role.rolePermissions) {
        permSet.add(rp.permission.name);
      }
    }
    return Array.from(permSet).sort();
  }

  private async toAuthUser(user: User): Promise<AuthUser> {
    const [roles, orgs, perms] = await Promise.all([
      this.loadRoles(user.id),
      this.loadOrgs(user.id),
      this.loadPerms(user.id),
    ]);

    return {
      id: user.id,
      email: user.email,
      name: user.name,
      roles,
      orgs,
      perms,
      domainId: user.domainId ?? null,
    };
  }

  private toPublicUser(user: User): PublicUser {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      status: user.status,
      emailVerifiedAt: user.emailVerifiedAt,
      createdAt: user.createdAt,
    };
  }

  /**
   * Signs a stateless RS256 access token carrying roles/orgs/perms as claims so
   * downstream services can authorize without calling UMS.
   */
  buildAccessToken(user: AuthUser, sessionId?: string): string {
    return this.jwtService.sign({
      sub: user.id,
      email: user.email,
      name: user.name,
      roles: user.roles,
      orgs: user.orgs,
      perms: user.perms,
      sid: sessionId,
      azp: JWT_AZP,
      dom: user.domainId ?? null,
    });
  }

  private async createSession(
    userId: string,
    family: string,
    meta: RequestMeta,
  ): Promise<{
    sessionId: string;
    refreshToken: string;
    refreshHash: string;
    expiresAt: Date;
  }> {
    const policies = await this.securityPoliciesService.getPolicies();

    // Enforce max concurrent sessions
    const activeSessions = await this.prisma.session.findMany({
      where: { userId, revokedAt: null },
      orderBy: { createdAt: 'asc' },
    });

    if (activeSessions.length >= policies.maxConcurrentSessions) {
      const sessionsToRevoke =
        activeSessions.length - policies.maxConcurrentSessions + 1;
      for (let i = 0; i < sessionsToRevoke; i++) {
        await this.prisma.session.update({
          where: { id: activeSessions[i].id },
          data: { revokedAt: new Date() },
        });
      }
    }

    const refreshToken = generateOpaqueToken();
    const refreshHash = sha256Hex(refreshToken);
    const expiresAt = new Date(
      Date.now() + policies.refreshTokenTtlDays * 24 * 60 * 60 * 1000,
    );

    const created = await this.prisma.session.create({
      data: {
        userId,
        refreshHash,
        family,
        userAgent: meta.userAgent ?? null,
        ip: meta.ip ?? null,
        expiresAt,
      },
    });

    return { sessionId: created.id, refreshToken, refreshHash, expiresAt };
  }

  async validateUser(
    email: string,
    password: string,
    domainIdentifier?: string,
  ): Promise<AuthUser | null> {
    await this.accountLockoutService.checkLockout(email);
    let user: User | null = null;
    if (domainIdentifier) {
      const domain = await this.prisma.domain.findFirst({
        where: {
          OR: [{ id: domainIdentifier }, { origin: domainIdentifier }],
          isActive: true,
        },
      });
      if (!domain) {
        throw new UnauthorizedException('Domain is not registered or inactive');
      }
      // Prioritas 1: akun khusus domain
      user = await this.usersRepository.findByEmailAndDomain(email, domain.id);
      // Prioritas 2: fallback ke akun global (domainId: null)
      if (!user) {
        user = await this.usersRepository.findByEmailAndDomain(email, null);
      }
    } else {
      // Tanpa domain identifier: cari akun global
      user = await this.usersRepository.findByEmailAndDomain(email, null);
    }

    if (!user || user.status !== $Enums.UserStatus.ACTIVE) {
      await this.accountLockoutService.recordFailedAttempt(email);
      return null;
    }

    const passwordMatches = await verifyPassword(user.passwordHash, password);
    if (!passwordMatches) {
      await this.accountLockoutService.recordFailedAttempt(email);
      return null;
    }

    await this.accountLockoutService.resetAttempts(email);
    const authUser = await this.toAuthUser(user);
    const policies = await this.securityPoliciesService.getPolicies();

    // Enforce MFA for admins
    if (policies.requireMfaForAdmins && authUser.roles.includes('ums:admin')) {
      const mfaFactor = await this.prisma.mfaFactor.findFirst({
        where: { userId: user.id, enabled: true },
      });
      if (!mfaFactor) {
        throw new ForbiddenException(
          'MFA is required for administrators. Please enroll in MFA.',
        );
      }
    }

    return authUser;
  }

  async validateUserById(id: string): Promise<AuthUser | null> {
    const user = await this.usersRepository.findById(id).catch(() => null);
    if (!user || user.status !== $Enums.UserStatus.ACTIVE) {
      return null;
    }
    return this.toAuthUser(user);
  }

  async register(dto: RegisterDto): Promise<PublicUser> {
    const existingUser = await this.usersRepository.findByEmail(dto.email);
    if (existingUser) {
      throw new BadRequestException('Email already in use');
    }

    this.passwordPolicyService.validatePasswordStrength(dto.password);

    const passwordHash = await hashPassword(dto.password);

    // v1 has no SMTP: registration is auto-verified.
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        passwordHash,
        name: dto.name ?? null,
        status: $Enums.UserStatus.ACTIVE,
        emailVerifiedAt: new Date(),
      },
    });

    await this.outboxService.emit('User', user.id, UMS_TOPICS.USER_CREATED, {
      eventId: randomUUID(),
      occurredAt: new Date().toISOString(),
      sourceService: 'ums-service',
      eventType: 'USER_CREATED',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        roles: [],
        orgs: [],
        status: user.status,
      },
    });

    return this.toPublicUser(user);
  }

  async login(user: AuthUser, meta: RequestMeta = {}): Promise<IssuedTokens> {
    const { sessionId, refreshToken } = await this.createSession(
      user.id,
      randomUUID(),
      meta,
    );

    await this.auditService.log({
      action: 'auth.login.success',
      actorId: user.id,
      ip: meta.ip ?? undefined,
      userAgent: meta.userAgent ?? undefined,
    });

    return {
      accessToken: this.buildAccessToken(user, sessionId),
      refreshToken,
      user,
    };
  }

  /**
   * Signs in an existing, active user identified by a federated (OIDC) email.
   * v1 policy: no auto-provisioning — the email must already match an ACTIVE
   * user (explicit linking). See platform-docs Q5 / ADR 0006.
   */
  async federatedLogin(
    email: string,
    meta: RequestMeta = {},
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    user: AuthUser;
  }> {
    const user = await this.usersRepository
      .findByEmail(email)
      .catch(() => null);
    if (!user || user.status !== $Enums.UserStatus.ACTIVE) {
      throw new UnauthorizedException('No linked account for this email');
    }
    return this.issueTokensForUser(user.id, meta);
  }

  /**
   * Issues a fresh token pair for an already-authenticated user
   * (used by the MFA challenge flow after successful TOTP verification).
   */
  async issueTokensForUser(
    userId: string,
    meta: RequestMeta = {},
  ): Promise<IssuedTokens> {
    const user = await this.usersRepository.findById(userId).catch(() => null);
    if (!user || user.status !== $Enums.UserStatus.ACTIVE) {
      throw new UnauthorizedException('User is not active');
    }
    const authUser = await this.toAuthUser(user);
    const { sessionId, refreshToken } = await this.createSession(
      user.id,
      randomUUID(),
      meta,
    );
    return {
      accessToken: this.buildAccessToken(authUser, sessionId),
      refreshToken,
      user: authUser,
    };
  }

  async refresh(
    rawToken: string,
    meta: RequestMeta = {},
  ): Promise<IssuedTokens> {
    const refreshHash = sha256Hex(rawToken);
    const session = await this.prisma.session.findUnique({
      where: { refreshHash },
    });

    if (!session) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Reuse detection: a rotated or revoked token presented again means the
    // token was stolen — burn every session in the family.
    if (session.revokedAt || session.replacedByHash) {
      await this.revokeFamily(session.family);
      await this.auditService.log({
        action: 'session.revoked',
        actorId: session.userId,
        severity: 'warn',
        subjectType: 'session',
        subjectId: session.id,
        ip: meta.ip ?? undefined,
        userAgent: meta.userAgent ?? undefined,
        metadata: { reason: 'refresh-token-reuse', family: session.family },
      });
      throw new UnauthorizedException('Refresh token reuse detected');
    }

    if (session.expiresAt.getTime() <= Date.now()) {
      await this.prisma.session.update({
        where: { id: session.id },
        data: { revokedAt: new Date() },
      });
      throw new UnauthorizedException('Refresh token expired');
    }

    const user = await this.usersRepository
      .findById(session.userId)
      .catch(() => null);
    if (!user || user.status !== $Enums.UserStatus.ACTIVE) {
      await this.revokeFamily(session.family);
      throw new UnauthorizedException('User is not active');
    }

    const authUser = await this.toAuthUser(user);
    const rotated = await this.createSession(user.id, session.family, meta);

    await this.prisma.session.update({
      where: { id: session.id },
      data: {
        revokedAt: new Date(),
        replacedByHash: rotated.refreshHash,
      },
    });

    await this.auditService.log({
      action: 'auth.refresh',
      actorId: authUser.id,
      ip: meta.ip ?? undefined,
      userAgent: meta.userAgent ?? undefined,
    });

    return {
      accessToken: this.buildAccessToken(authUser),
      refreshToken: rotated.refreshToken,
      user: authUser,
    };
  }

  async logout(rawToken: string): Promise<void> {
    const refreshHash = sha256Hex(rawToken);
    const session = await this.prisma.session.findUnique({
      where: { refreshHash },
    });

    if (session && !session.revokedAt) {
      await this.prisma.session.update({
        where: { id: session.id },
        data: { revokedAt: new Date() },
      });
      await this.auditService.log({
        action: 'auth.logout',
        actorId: session.userId,
        subjectType: 'session',
        subjectId: session.id,
      });
    }
  }

  async logoutAll(userId: string): Promise<void> {
    const result = await this.prisma.session.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    await this.auditService.log({
      action: 'session.revoked',
      actorId: userId,
      metadata: { reason: 'logout-all', count: result.count },
    });
  }

  async me(userId: string): Promise<AuthUser> {
    const user = await this.usersRepository.findById(userId).catch(() => null);
    if (!user || user.status !== $Enums.UserStatus.ACTIVE) {
      throw new UnauthorizedException('User is not active');
    }
    return this.toAuthUser(user);
  }
  private async revokeFamily(family: string): Promise<void> {
    await this.prisma.session.updateMany({
      where: { family, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  async cleanupExpiredSessions(): Promise<number> {
    const result = await this.prisma.session.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });
    return result.count;
  }

  get accessTokenExpiresInSeconds(): number {
    return this.accessTokenTtlSeconds;
  }

  /**
   * TTL for PASSWORD_RESET tokens, sourced from AUTH_TOKEN_TTL_MINUTES
   * (default 60 minutes — contract 001, never hardcoded).
   */
  private getPasswordResetTtlMinutes(): number {
    const raw = this.configService.get<string | number>(
      'AUTH_TOKEN_TTL_MINUTES',
    );
    const parsed = Number(raw);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 60;
  }

  /**
   * TTL for EMAIL_VERIFY tokens, sourced from AUTH_TOKEN_TTL_HOURS
   * (default 24 hours — contract 001, never hardcoded).
   */
  private getEmailVerifyTtlHours(): number {
    const raw = this.configService.get<string | number>('AUTH_TOKEN_TTL_HOURS');
    const parsed = Number(raw);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 24;
  }

  /**
   * Issues a single-use PASSWORD_RESET AuthToken when the email belongs to an
   * active user. Anti-enumeration: the response and the amount of work are
   * identical whether or not the email exists — the unknown-email branch pays
   * a dummy argon2id hash to equalize timing. Delivery of the raw token to
   * the user is slice 5's concern; here it is only logged (hash, never raw).
   */
  async requestPasswordReset(email: string): Promise<void> {
    const policies = await this.securityPoliciesService.getPolicies();
    if (!policies.allowPasswordReset) {
      throw new BadRequestException(
        'Password reset is disabled by security policy',
      );
    }

    const user = await this.usersRepository
      .findByEmail(email)
      .catch(() => null);

    if (!user || user.status !== $Enums.UserStatus.ACTIVE) {
      // Burn equivalent CPU work so response timing does not reveal account existence.
      await hashPassword('timing-equalizer-not-a-real-password');
      return;
    }

    const rawToken = generateOpaqueToken();
    const tokenHash = sha256Hex(rawToken);
    const expiresAt = new Date(
      Date.now() + this.getPasswordResetTtlMinutes() * 60_000,
    );

    await this.authTokensRepository.createPasswordResetToken(
      user.id,
      tokenHash,
      expiresAt,
    );

    // Delivery (ADR 0004): the sender never throws and never changes the
    // response — a mail failure is captured inside the mail module.
    const webUrl =
      this.configService.get<string>('APP_WEB_URL') ?? 'http://localhost:5173';
    await this.mailSender.sendPasswordReset(
      user.email,
      rawToken,
      `${webUrl.replace(/\/$/, '')}/reset-password`,
    );
  }

  /**
   * Consumes a PASSWORD_RESET token: replaces the password hash (argon2id),
   * marks the token used, and revokes every active session of the user.
   * Invalid, expired, and used tokens collapse into one identical error.
   */
  async resetPassword(token: string, newPassword: string): Promise<void> {
    const policies = await this.securityPoliciesService.getPolicies();
    if (!policies.allowPasswordReset) {
      throw new BadRequestException(
        'Password reset is disabled by security policy',
      );
    }

    const tokenHash = sha256Hex(token);
    const authToken =
      await this.authTokensRepository.findValidPasswordResetToken(tokenHash);

    if (!authToken) {
      throw new BadRequestException('Token is invalid or expired');
    }

    this.passwordPolicyService.validatePasswordStrength(newPassword);
    await this.passwordPolicyService.checkPasswordHistory(
      authToken.userId,
      newPassword,
    );

    const newPasswordHash = await hashPassword(newPassword);

    await this.authTokensRepository.consumePasswordResetToken({
      tokenId: authToken.id,
      newPasswordHash,
      userId: authToken.userId,
    });

    await this.passwordPolicyService.recordPasswordHistory(
      authToken.userId,
      newPasswordHash,
    );

    await this.auditService.log({
      action: 'auth.password_reset_completed',
      actorId: authToken.userId,
      severity: 'warn',
    });
    this.webhookDispatcherService
      .dispatch('user.password_reset_completed', { userId: authToken.userId })
      .catch(() => {});
  }

  /**
   * Consumes an EMAIL_VERIFY token: marks it used and fills
   * users.emailVerifiedAt. Invalid, expired, and used tokens collapse into
   * one identical error. A verified email is never reset by token traffic.
   */
  async verifyEmail(token: string): Promise<void> {
    const tokenHash = sha256Hex(token);
    const authToken =
      await this.authTokensRepository.findValidEmailVerifyToken(tokenHash);

    if (!authToken) {
      throw new BadRequestException('Token is invalid or expired');
    }

    await this.authTokensRepository.consumeEmailVerifyToken({
      tokenId: authToken.id,
      userId: authToken.userId,
    });

    await this.auditService.log({
      action: 'auth.email_verified',
      actorId: authToken.userId,
    });
    this.webhookDispatcherService
      .dispatch('user.email_verified', { userId: authToken.userId })
      .catch(() => {});
  }

  /**
   * Issues a fresh EMAIL_VERIFY AuthToken when the email belongs to an active
   * user whose emailVerifiedAt is still null. Anti-enumeration: unknown,
   * blocked, and already-verified emails pay the same dummy hash work and
   * return the identical neutral response.
   */
  async resendVerification(email: string): Promise<void> {
    const user = await this.usersRepository
      .findByEmail(email)
      .catch(() => null);

    if (
      !user ||
      user.status !== $Enums.UserStatus.ACTIVE ||
      user.emailVerifiedAt !== null
    ) {
      await hashPassword('timing-equalizer-not-a-real-password');
      return;
    }

    const rawToken = generateOpaqueToken();
    const tokenHash = sha256Hex(rawToken);
    const expiresAt = new Date(
      Date.now() + this.getEmailVerifyTtlHours() * 3_600_000,
    );

    await this.authTokensRepository.createEmailVerifyToken(
      user.id,
      tokenHash,
      expiresAt,
    );

    // Delivery (ADR 0004): the sender never throws and never changes the
    // response — a mail failure is captured inside the mail module.
    const webUrl =
      this.configService.get<string>('APP_WEB_URL') ?? 'http://localhost:5173';
    await this.mailSender.sendEmailVerification(
      user.email,
      rawToken,
      `${webUrl.replace(/\/$/, '')}/verify-email`,
    );
  }
}
