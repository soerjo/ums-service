import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service.js';

@Injectable()
export class AccountLockoutService {
  constructor(private readonly prisma: PrismaService) {}

  async checkLockout(identifier: string): Promise<void> {
    const attempt = await this.prisma.loginAttempt.findUnique({
      where: { identifier },
    });

    if (attempt?.lockedUntil && attempt.lockedUntil > new Date()) {
      const remainingMinutes = Math.ceil(
        (attempt.lockedUntil.getTime() - Date.now()) / (60 * 1000),
      );
      throw new ForbiddenException(
        `Account is temporarily locked due to excessive failed login attempts. Try again in ${remainingMinutes} minute(s).`,
      );
    }
  }

  async recordFailedAttempt(
    identifier: string,
    ip?: string,
    maxAttempts = 5,
    lockDurationMinutes = 15,
  ): Promise<void> {
    const now = new Date();
    const attempt = await this.prisma.loginAttempt.findUnique({
      where: { identifier },
    });

    if (!attempt) {
      await this.prisma.loginAttempt.create({
        data: {
          identifier,
          ip: ip ?? null,
          attempts: 1,
          lastAttemptAt: now,
        },
      });
      return;
    }

    const newAttempts = attempt.attempts + 1;
    let lockedUntil: Date | null = attempt.lockedUntil;

    if (newAttempts >= maxAttempts) {
      lockedUntil = new Date(now.getTime() + lockDurationMinutes * 60 * 1000);
    }

    await this.prisma.loginAttempt.update({
      where: { identifier },
      data: {
        attempts: newAttempts,
        ip: ip ?? attempt.ip,
        lockedUntil,
        lastAttemptAt: now,
      },
    });
  }

  async resetAttempts(identifier: string): Promise<void> {
    try {
      await this.prisma.loginAttempt.delete({
        where: { identifier },
      });
    } catch {
      // Ignore if record doesn't exist
    }
  }
}
