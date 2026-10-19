import { Test, type TestingModule } from '@nestjs/testing';
import { SecurityPoliciesService } from './security-policies.service.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import { SecurityPolicyKeyEnum } from './security-policies.types.js';

describe('SecurityPoliciesService', () => {
  let service: SecurityPoliciesService;

  const mockPrisma = {
    securityPolicy: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      upsert: jest.fn(),
    },
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    mockPrisma.securityPolicy.findMany.mockResolvedValue([]);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SecurityPoliciesService,
        {
          provide: PrismaService,
          useValue: mockPrisma,
        },
      ],
    }).compile();

    service = module.get<SecurityPoliciesService>(SecurityPoliciesService);
  });

  it('should seed default policies on onModuleInit if none exist', async () => {
    mockPrisma.securityPolicy.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([
        { key: 'accessTokenTtlSeconds', value: 900 },
        { key: 'maxActiveSessionsPerUser', value: 5 },
        { key: 'enforceMfa', value: false },
      ]);

    await service.onModuleInit();

    expect(mockPrisma.securityPolicy.create).toHaveBeenCalledTimes(3);
    expect(
      service.getPolicy(SecurityPolicyKeyEnum.AccessTokenTtlSeconds, 300),
    ).toBe(900);
  });

  it('should return cached policy value without hitting database', async () => {
    mockPrisma.securityPolicy.findMany.mockResolvedValue([
      { key: 'maxActiveSessionsPerUser', value: 10 },
    ]);
    await service.onModuleInit();

    const result = service.getPolicy(
      SecurityPolicyKeyEnum.MaxActiveSessionsPerUser,
      5,
    );
    expect(result).toBe(10);
  });

  it('should update database and memory cache on setPolicy', async () => {
    mockPrisma.securityPolicy.upsert.mockResolvedValue({
      key: 'enforceMfa',
      value: true,
      updatedBy: 'admin-1',
    });

    const updated = await service.setPolicy('enforceMfa', true, 'admin-1');

    expect(mockPrisma.securityPolicy.upsert).toHaveBeenCalledWith({
      where: { key: 'enforceMfa' },
      update: { value: true, updatedBy: 'admin-1', description: undefined },
      create: {
        key: 'enforceMfa',
        value: true,
        updatedBy: 'admin-1',
        description: undefined,
      },
    });
    expect(updated.value).toBe(true);
    expect(service.getPolicy(SecurityPolicyKeyEnum.EnforceMfa, false)).toBe(
      true,
    );
  });
});
