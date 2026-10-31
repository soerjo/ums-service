import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UserStatus } from '@prisma/client';
import type { User } from '@prisma/client';
import { UsersRepository } from '../users/users.repository.js';
import type { PrismaService } from '../../prisma/prisma.service.js';
import { AuditService } from '../audit/audit.service.js';
import { AuthService } from './auth.service.js';
import { WebhookDispatcherService } from '../clients/webhook-dispatcher.service.js';
import { SecurityPoliciesService } from '../security-policies/security-policies.service.js';
import { OutboxService } from '../outbox/outbox.service.js';
import { PasswordPolicyService } from './password-policy.service.js';
import { AccountLockoutService } from './account-lockout.service.js';
import { hashPassword } from '../../common/utils/password.util.js';
import { sha256Hex } from '../../common/utils/hash.util.js';
import type { AuthUser } from '../../common/interfaces/auth-user.interface.js';
import { AuthTokensRepository } from './auth-tokens.repository.js';

interface FakeSession {
  id: string;
  userId: string;
  refreshHash: string;
  family: string;
  userAgent: string | null;
  ip: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  replacedByHash: string | null;
}

interface SessionUpdateArgs {
  where: { id: string };
  data: Partial<FakeSession>;
}

interface SessionUpdateManyArgs {
  where: { family?: string; userId?: string; revokedAt: null };
  data: { revokedAt: Date };
}

describe('AuthService', () => {
  let service: AuthService;
  let prismaService: unknown;
  let sessions: FakeSession[];
  let findById: jest.Mock;
  let findByEmail: jest.Mock;
  let findByEmailAndDomain: jest.Mock;
  let updateManySession: jest.Mock;
  let updateSession: jest.Mock;
  let createUser: jest.Mock;
  let userRoleFindMany: jest.Mock;
  let orgMemberFindMany: jest.Mock;
  let mockSecurityPoliciesService: Partial<SecurityPoliciesService>;
  const fullUser = {
    id: 'user-1',
    email: 'user@example.com',
    name: 'Ada Lovelace',
    passwordHash: '',
    status: UserStatus.ACTIVE,
    emailVerifiedAt: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  } as User;

  const authUser: AuthUser = {
    id: 'user-1',
    email: 'user@example.com',
    name: 'Ada Lovelace',
    avatarUrl: null,
    phone: null,
    roles: ['ums:admin'],
    orgs: ['pesanggrahan'],
    perms: ['users:read'],
    domainId: null,
  };

  beforeEach(() => {
    sessions = [];
    findById = jest.fn();
    findByEmail = jest.fn();
    findByEmailAndDomain = jest
      .fn()
      .mockImplementation(
        (email: string, domainId: string | null) =>
          findByEmail(email, domainId) as Promise<User | null>,
      );
    createUser = jest.fn();
    userRoleFindMany = jest
      .fn()
      .mockResolvedValue([
        { role: { name: 'ums:admin', rolePermissions: [] } },
      ]);
    orgMemberFindMany = jest.fn().mockResolvedValue([]);
    const mockAuthTokensRepository = {
      createPasswordResetToken: jest.fn(),
      findValidPasswordResetToken: jest.fn(),
      consumePasswordResetToken: jest.fn(),
      findValidEmailVerifyToken: jest.fn(),
      consumeEmailVerifyToken: jest.fn(),
      createEmailVerifyToken: jest.fn(),
    };
    mockSecurityPoliciesService = {
      getPolicies: jest.fn().mockResolvedValue({
        accessTokenTtlMinutes: 15,
        refreshTokenTtlDays: 30,
        maxConcurrentSessions: 5,
        requireMfaForAdmins: true,
        enableAuditRetentionDays: 30,
        allowPasswordReset: true,
      }),
    };

    prismaService = {
      session: {
        create: jest.fn(({ data }: { data: FakeSession }) => {
          const session: FakeSession = {
            id: `session-${sessions.length + 1}`,
            userId: data.userId,
            refreshHash: data.refreshHash,
            family: data.family,
            userAgent: data.userAgent ?? null,
            ip: data.ip ?? null,
            expiresAt: data.expiresAt,
            revokedAt: null,
            replacedByHash: null,
          };
          sessions.push(session);
          return Promise.resolve(session);
        }),
        findUnique: jest.fn(({ where }: { where: { refreshHash: string } }) =>
          Promise.resolve(
            sessions.find((s) => s.refreshHash === where.refreshHash) ?? null,
          ),
        ),
        update: jest.fn(({ where, data }: SessionUpdateArgs) => {
          const session = sessions.find((s) => s.id === where.id);
          if (session) {
            Object.assign(session, data);
          }
          return Promise.resolve(session);
        }),
        updateMany: jest.fn(({ where, data }: SessionUpdateManyArgs) => {
          let count = 0;
          for (const session of sessions) {
            const matchesFamily = where.family
              ? session.family === where.family
              : true;
            const matchesUser = where.userId
              ? session.userId === where.userId
              : true;
            const matchesActive = session.revokedAt === null;
            if (matchesFamily && matchesUser && matchesActive) {
              session.revokedAt = data.revokedAt;
              count += 1;
            }
          }
          return Promise.resolve({ count });
        }),
        findMany: jest.fn(() => Promise.resolve(sessions)),
      },
      userRole: { findMany: userRoleFindMany },
      orgMember: { findMany: orgMemberFindMany },
      user: {
        create: createUser,
        update: jest.fn(),
        findUnique: jest.fn(),
      },
      securityPolicy: {
        findUnique: jest.fn().mockResolvedValue(null),
        findFirst: jest.fn().mockResolvedValue(null),
      },
      mfaFactor: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'mfa-1',
          userId: 'user-1',
          secret: 'SECRET',
          enabled: true,
        }),
      },
      domain: {
        findFirst: jest
          .fn()
          .mockImplementation(
            ({
              where,
            }: {
              where: { OR?: Array<{ id?: string; origin?: string }> };
            }) => {
              if (
                where?.OR?.some(
                  (c) =>
                    c.id === 'invalid-domain' || c.origin === 'invalid-domain',
                )
              ) {
                return null;
              }
              return {
                id: 'dom-1',
                name: 'Domain 1',
                origin: 'https://app1.test',
                isActive: true,
              };
            },
          ),
      },
    };

    const configService = {
      get: jest.fn((key: string) =>
        key === 'JWT_ACCESS_EXPIRATION'
          ? '15m'
          : key === 'JWT_REFRESH_EXPIRATION'
            ? '30d'
            : undefined,
      ),
    };

    const jwtService = {
      sign: jest.fn(() => 'signed-access-token'),
      verify: jest.fn(),
    };

    const prismaMock = prismaService as {
      session: { updateMany: jest.Mock; update: jest.Mock };
      user: { update: jest.Mock };
    };
    updateManySession = prismaMock.session.updateMany;
    updateSession = prismaMock.session.update;
    service = new AuthService(
      {
        findById,
        findByEmail,
        findByEmailAndDomain,
      } as unknown as UsersRepository,
      jwtService as unknown as JwtService,
      configService as unknown as ConfigService,
      prismaService as PrismaService,
      mockAuthTokensRepository as unknown as AuthTokensRepository,
      { sendPasswordReset: jest.fn(), sendEmailVerification: jest.fn() },
      {
        log: jest.fn().mockResolvedValue(undefined),
      } as unknown as AuditService,
      {
        dispatch: jest.fn().mockResolvedValue([]),
      } as unknown as WebhookDispatcherService,
      mockSecurityPoliciesService as unknown as SecurityPoliciesService,
      { emit: jest.fn().mockResolvedValue({}) } as unknown as OutboxService,
      {
        validatePasswordStrength: jest.fn(),
        checkPasswordHistory: jest.fn().mockResolvedValue(undefined),
        recordPasswordHistory: jest.fn().mockResolvedValue(undefined),
      } as unknown as PasswordPolicyService,
      {
        checkLockout: jest.fn().mockResolvedValue(undefined),
        recordFailedAttempt: jest.fn().mockResolvedValue(undefined),
        resetAttempts: jest.fn().mockResolvedValue(undefined),
      } as unknown as AccountLockoutService,
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('login', () => {
    it('returns the profile for an active user', async () => {
      findById.mockResolvedValue(fullUser);
      userRoleFindMany.mockResolvedValue([]);
      orgMemberFindMany.mockResolvedValue([]);

      const result = await service.me(fullUser.id);
      expect(result.id).toBe(fullUser.id);
      expect(result.email).toBe(fullUser.email);
    });

    it('updates user profile fields and returns updated user', async () => {
      findById.mockResolvedValue(fullUser);
      userRoleFindMany.mockResolvedValue([]);
      orgMemberFindMany.mockResolvedValue([]);
      const prismaMock = prismaService as {
        user: { update: jest.Mock };
      };
      const mockUpdate = prismaMock.user.update;
      mockUpdate.mockResolvedValue({
        ...fullUser,
        name: 'Ada Lovelace Updated',
        avatarUrl: 'https://minio.test/avatar.png',
        phone: '+62812345678',
      });

      const result = await service.updateProfile(fullUser.id, {
        name: 'Ada Lovelace Updated',
        avatarUrl: 'https://minio.test/avatar.png',
        phone: '+62812345678',
      });

      expect(result.name).toBe('Ada Lovelace Updated');
      expect(result.avatarUrl).toBe('https://minio.test/avatar.png');
      expect(result.phone).toBe('+62812345678');
    });

    it('stores only the sha256 hash of the refresh token', async () => {
      const result = await service.login(authUser);

      expect(result.accessToken).toBe('signed-access-token');
      expect(result.user).toEqual(authUser);
      expect(sessions).toHaveLength(1);
      expect(sessions[0].refreshHash).toBe(sha256Hex(result.refreshToken));
      expect(sessions[0].refreshHash).not.toBe(result.refreshToken);
    });
  });

  describe('refresh rotation', () => {
    it('rotates the token and marks the old session as replaced', async () => {
      findById.mockResolvedValue(fullUser);
      const login = await service.login(authUser);

      const rotated = await service.refresh(login.refreshToken);

      const oldSession = sessions.find(
        (s) => s.refreshHash === sha256Hex(login.refreshToken),
      );
      expect(oldSession?.replacedByHash).toBe(sha256Hex(rotated.refreshToken));
      expect(oldSession?.revokedAt).toBeInstanceOf(Date);
      expect(rotated.refreshToken).not.toBe(login.refreshToken);
      expect(sessions).toHaveLength(2);
      expect(updateSession).toHaveBeenCalled();
    });

    it('keeps the rotated session in the same family', async () => {
      findById.mockResolvedValue(fullUser);
      const login = await service.login(authUser);

      await service.refresh(login.refreshToken);

      const families = new Set(sessions.map((s) => s.family));
      expect(families.size).toBe(1);
    });

    it('detects reuse of a rotated token and revokes the whole family', async () => {
      findById.mockResolvedValue(fullUser);
      const login = await service.login(authUser);
      await service.refresh(login.refreshToken);

      await expect(service.refresh(login.refreshToken)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );

      const reuseCall = (
        updateManySession.mock.calls[0] as [SessionUpdateManyArgs]
      )[0];
      expect(reuseCall.where.revokedAt).toBeNull();
      expect(sessions.every((s) => s.revokedAt instanceof Date)).toBe(true);
    });

    it('rejects an unknown refresh token', async () => {
      await expect(service.refresh('not-a-real-token')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('rejects an expired session and revokes it', async () => {
      const login = await service.login(authUser);
      const session = sessions[0];
      session.expiresAt = new Date(Date.now() - 1000);

      await expect(service.refresh(login.refreshToken)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
      expect(session.revokedAt).toBeInstanceOf(Date);
    });

    it('revokes the family when the user is no longer active', async () => {
      findById.mockResolvedValue({ ...fullUser, status: UserStatus.BLOCKED });
      const login = await service.login(authUser);

      await expect(service.refresh(login.refreshToken)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
      expect(sessions[0].revokedAt).toBeInstanceOf(Date);
    });

    it('rejects when the user no longer exists', async () => {
      findById.mockResolvedValue(null);
      const login = await service.login(authUser);

      await expect(service.refresh(login.refreshToken)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });
  });

  describe('logout', () => {
    it('revokes the session matching the refresh token', async () => {
      const login = await service.login(authUser);

      await service.logout(login.refreshToken);

      expect(sessions[0].revokedAt).toBeInstanceOf(Date);
    });

    it('is a no-op for an unknown token', async () => {
      await expect(service.logout('unknown')).resolves.toBeUndefined();
    });
  });

  describe('logoutAll', () => {
    it('revokes every active session for the user', async () => {
      await service.login(authUser);
      await service.login(authUser);

      await service.logoutAll(authUser.id);

      expect(sessions.every((s) => s.revokedAt instanceof Date)).toBe(true);
    });
  });

  describe('validateUser', () => {
    it('returns roles/orgs/perms for valid credentials', async () => {
      const passwordHash = await hashPassword('secret-password');
      findByEmail.mockResolvedValue({ ...fullUser, passwordHash });
      userRoleFindMany.mockResolvedValue([
        {
          role: {
            name: 'ums:admin',
            rolePermissions: [{ permission: { name: 'users:read' } }],
          },
        },
      ]);
      orgMemberFindMany.mockResolvedValue([
        { organization: { name: 'pesanggrahan' } },
      ]);

      await expect(
        service.validateUser('user@example.com', 'secret-password'),
      ).resolves.toEqual(authUser);
    });

    it('rejects a blocked user', async () => {
      findByEmail.mockResolvedValue({
        ...fullUser,
        status: UserStatus.BLOCKED,
      });

      await expect(
        service.validateUser('user@example.com', 'secret-password'),
      ).resolves.toBeNull();
    });

    it('rejects a wrong password', async () => {
      const passwordHash = await hashPassword('secret-password');
      findByEmail.mockResolvedValue({ ...fullUser, passwordHash });

      await expect(
        service.validateUser('user@example.com', 'wrong-password'),
      ).resolves.toBeNull();
    });

    it('authenticates with domain identifier and returns domain user', async () => {
      const passwordHash = await hashPassword('secret-password');
      const domainUser: User = {
        ...fullUser,
        id: 'user-dom',
        domainId: 'dom-1',
        passwordHash,
      };
      findByEmail.mockResolvedValue(domainUser);
      userRoleFindMany.mockResolvedValue([
        {
          role: {
            name: 'domain:admin',
            rolePermissions: [{ permission: { name: 'users:read' } }],
          },
        },
      ]);
      orgMemberFindMany.mockResolvedValue([]);

      const result = await service.validateUser(
        'user@example.com',
        'secret-password',
        'dom-1',
      );
      expect(result).not.toBeNull();
      expect(result?.domainId).toBe('dom-1');
    });

    it('throws UnauthorizedException if domain is not registered or inactive', async () => {
      const passwordHash = await hashPassword('secret-password');
      findByEmail.mockResolvedValue({ ...fullUser, passwordHash });

      await expect(
        service.validateUser(
          'user@example.com',
          'secret-password',
          'invalid-domain',
        ),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('register', () => {
    it('hashes the password and auto-verifies the email', async () => {
      findByEmail.mockResolvedValue(null);
      createUser.mockImplementation(
        ({ data }: { data: { passwordHash: string; email: string } }) =>
          Promise.resolve({
            ...fullUser,
            id: 'new-user',
            email: data.email,
            passwordHash: data.passwordHash,
          }),
      );

      const result = await service.register({
        email: 'user@example.com',
        password: 'secret-password',
        name: 'Ada',
      });

      interface CreateUserArgs {
        data: {
          email: string;
          name?: string;
          status: UserStatus;
          emailVerifiedAt: Date;
          passwordHash: string;
        };
      }
      const createCall = (createUser.mock.calls[0] as [CreateUserArgs])[0];
      expect(createCall.data.email).toBe('user@example.com');
      expect(createCall.data.name).toBe('Ada');
      expect(createCall.data.status).toBe(UserStatus.ACTIVE);
      expect(createCall.data.emailVerifiedAt).toBeInstanceOf(Date);
      expect(typeof createCall.data.passwordHash).toBe('string');
      expect(createCall.data.passwordHash).not.toBe('secret-password');
      expect(result).not.toHaveProperty('passwordHash');
      expect(result.email).toBe('user@example.com');
    });

    it('rejects a duplicate email', async () => {
      findByEmail.mockResolvedValue(fullUser);

      await expect(
        service.register({
          email: 'user@example.com',
          password: 'secret-password',
        }),
      ).rejects.toThrow('Email already in use');
    });
  });

  describe('cleanupExpiredSessions', () => {
    it('deletes sessions with expiresAt in the past', async () => {
      sessions.push(
        {
          id: 'exp-1',
          userId: 'user-1',
          refreshHash: 'hash-1',
          family: 'fam-1',
          userAgent: null,
          ip: null,
          expiresAt: new Date(Date.now() - 10000),
          revokedAt: null,
          replacedByHash: null,
        },
        {
          id: 'valid-1',
          userId: 'user-1',
          refreshHash: 'hash-2',
          family: 'fam-2',
          userAgent: null,
          ip: null,
          expiresAt: new Date(Date.now() + 10000),
          revokedAt: null,
          replacedByHash: null,
        },
      );

      const deleteManyMock = jest.fn().mockResolvedValue({ count: 1 });
      const prismaRef = (
        service as unknown as {
          prisma: { session: { deleteMany: jest.Mock } };
        }
      ).prisma;
      prismaRef.session.deleteMany = deleteManyMock;

      const count = await service.cleanupExpiredSessions();
      expect(count).toBe(1);
      expect(deleteManyMock).toHaveBeenCalledWith({
        where: {
          expiresAt: {
            lt: expect.any(Date) as Date,
          },
        },
      });
    });
  });
});
