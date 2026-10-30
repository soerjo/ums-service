import { Injectable, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service.js';
import { verifyPassword } from '../../common/utils/password.util.js';
import type { Prisma } from '@prisma/client';

const COMMON_LEAKED_PASSWORDS = new Set([
  '123456',
  '12345678',
  '123456789',
  'password',
  'password123',
  'admin123',
  'qwerty',
  'qwertyuiop',
  'welcome123',
  'letmein123',
  'iloveyou',
  'sunshine',
  'princess',
  'football',
  'monkey123',
]);

@Injectable()
export class PasswordPolicyService {
  constructor(private readonly prisma: PrismaService) {}

  validatePasswordStrength(password: string): void {
    if (password.length < 8) {
      throw new BadRequestException(
        'Password must be at least 8 characters long',
      );
    }

    if (COMMON_LEAKED_PASSWORDS.has(password.toLowerCase())) {
      throw new BadRequestException(
        'Password is too common or known to be breached. Please choose a more secure password.',
      );
    }
  }

  async checkPasswordHistory(
    userId: string,
    plainPassword: string,
    historyLimit = 3,
  ): Promise<void> {
    const histories = await this.prisma.passwordHistory.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: historyLimit,
    });

    for (const record of histories) {
      const match = await verifyPassword(plainPassword, record.passwordHash);
      if (match) {
        throw new BadRequestException(
          'Password has been used recently. Please choose a different password.',
        );
      }
    }
  }

  async recordPasswordHistory(
    userId: string,
    passwordHash: string,
    tx?: Prisma.TransactionClient,
  ): Promise<void> {
    const client = tx || this.prisma;
    await client.passwordHistory.create({
      data: {
        userId,
        passwordHash,
      },
    });
  }
}
