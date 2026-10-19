import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import { generateSecret, generateURI, verify } from 'otplib';
import { MfaRepository } from './mfa.repository.js';
import { UsersService } from '../users/users.service.js';
import { WebhookDispatcherService } from '../clients/webhook-dispatcher.service.js';
import { encryptSecret, decryptSecret } from './encryption.util.js';

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const ISSUER = 'UMS';

interface MfaChallenge {
  userId: string;
  expiresAt: number;
}

export interface EnrollResult {
  secret: string;
  otpauthUri: string;
}

export interface ConfirmResult {
  enabled: true;
  recoveryCodes: string[];
}

@Injectable()
export class MfaService {
  private readonly challenges = new Map<string, MfaChallenge>();

  constructor(
    private readonly mfaRepository: MfaRepository,
    private readonly usersService: UsersService,
    private readonly webhookDispatcherService: WebhookDispatcherService,
  ) {}

  /** True when the user has an enabled TOTP factor and must pass a challenge. */
  async isEnabled(userId: string): Promise<boolean> {
    const factor = await this.mfaRepository.findActiveByUserAndType(
      userId,
      'totp',
    );
    return Boolean(factor && factor.enabled);
  }

  async enroll(userId: string): Promise<EnrollResult> {
    const existing = await this.mfaRepository.findByUser(userId);
    if (existing && existing.enabled) {
      throw new BadRequestException('MFA is already enabled for this user');
    }

    const secret = generateSecret();
    const accountName = await this.usersService.getEmail(userId);

    const otpauthUri = generateURI({
      issuer: ISSUER,
      label: accountName,
      secret,
    });

    const data = {
      type: 'totp',
      secret: encryptSecret(secret, process.env.APP_ENCRYPTION_KEY!),
      enabled: false,
      confirmedAt: null,
      recoveryCodes: [],
    };

    if (existing) {
      await this.mfaRepository.update(existing.id, data);
    } else {
      await this.mfaRepository.create({ userId, ...data });
    }

    return { secret, otpauthUri };
  }

  async confirm(userId: string, code: string): Promise<ConfirmResult> {
    const factor = await this.mfaRepository.findByUser(userId);
    if (!factor) {
      throw new NotFoundException('No pending MFA enrollment found');
    }
    if (factor.enabled) {
      throw new BadRequestException('MFA is already enabled for this user');
    }

    const secret = decryptSecret(
      factor.secret,
      process.env.APP_ENCRYPTION_KEY!,
    );
    const result = await verify({
      token: code,
      secret,
      strategy: 'totp',
      epochTolerance: [5, 0],
    });
    if (!result.valid) {
      throw new BadRequestException('Invalid TOTP code');
    }

    const recoveryCodes = this.generateRecoveryCodes();
    const hashedRecoveryCodes = recoveryCodes.map((code) =>
      this.hashRecoveryCode(code),
    );

    await this.mfaRepository.update(factor.id, {
      enabled: true,
      confirmedAt: new Date(),
      recoveryCodes: hashedRecoveryCodes,
    });

    this.webhookDispatcherService
      .dispatch('user.mfa_enabled', { userId })
      .catch(() => {});
    return { enabled: true, recoveryCodes };
  }

  async disable(userId: string, password: string): Promise<void> {
    const valid = await this.usersService.validatePassword(userId, password);
    if (!valid) {
      throw new ForbiddenException('Invalid password');
    }

    const factor = await this.mfaRepository.findByUser(userId);
    if (!factor || !factor.enabled) {
      throw new NotFoundException('MFA is not enabled for this user');
    }

    await this.mfaRepository.delete(factor.id);
    this.webhookDispatcherService
      .dispatch('user.mfa_disabled', { userId })
      .catch(() => {});
  }

  /**
   * Creates a 5-minute challenge for a user with MFA enabled.
   * Called by the auth service after a successful password check.
   */
  async createChallenge(userId: string): Promise<{
    mfaRequired: true;
    challengeId: string;
    expiresIn: number;
  }> {
    const factor = await this.mfaRepository.findActiveByUserAndType(
      userId,
      'totp',
    );
    if (!factor) {
      throw new NotFoundException('MFA is not enabled for this user');
    }

    const challengeId = randomBytes(24).toString('hex');
    this.challenges.set(challengeId, {
      userId,
      expiresAt: Date.now() + CHALLENGE_TTL_MS,
    });

    return {
      mfaRequired: true,
      challengeId,
      expiresIn: Math.floor(CHALLENGE_TTL_MS / 1000),
    };
  }

  /**
   * Verifies a challenge code (TOTP or recovery code) and returns the userId.
   * Throws if the challenge is unknown/expired or the code is invalid.
   */
  async verifyChallenge(
    challengeId: string,
    code: string,
  ): Promise<{ userId: string }> {
    const challenge = this.challenges.get(challengeId);
    if (!challenge || challenge.expiresAt < Date.now()) {
      this.challenges.delete(challengeId);
      throw new BadRequestException('Invalid or expired challenge');
    }

    const factor = await this.mfaRepository.findActiveByUserAndType(
      challenge.userId,
      'totp',
    );
    if (!factor) {
      this.challenges.delete(challengeId);
      throw new BadRequestException('Invalid or expired challenge');
    }

    const secret = decryptSecret(
      factor.secret,
      process.env.APP_ENCRYPTION_KEY!,
    );
    let isValidTotp = false;
    try {
      const result = await verify({
        token: code,
        secret,
        strategy: 'totp',
        epochTolerance: [5, 0],
      });
      isValidTotp = result.valid;
    } catch {
      isValidTotp = false;
    }
    const isValidRecovery = await this.consumeRecoveryCode(factor, code);

    if (!isValidTotp && !isValidRecovery) {
      throw new BadRequestException('Invalid TOTP code');
    }

    this.challenges.delete(challengeId);
    return { userId: challenge.userId };
  }

  private async consumeRecoveryCode(
    factor: { id: string; recoveryCodes: string[] },
    code: string,
  ): Promise<boolean> {
    const stored = factor.recoveryCodes ?? [];
    const hashed = this.hashRecoveryCode(code);
    const idx = stored.indexOf(hashed);
    if (idx === -1) return false;

    const remaining = stored.filter((_, i) => i !== idx);
    await this.mfaRepository.update(factor.id, {
      recoveryCodes: remaining,
    });
    return true;
  }

  private generateRecoveryCodes(): string[] {
    return Array.from({ length: 8 }, () =>
      randomBytes(5).toString('hex').toUpperCase(),
    );
  }

  private hashRecoveryCode(code: string): string {
    return createHash('sha256').update(code).digest('hex');
  }
}
