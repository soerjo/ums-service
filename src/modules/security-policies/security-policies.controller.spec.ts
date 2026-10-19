import { Test, type TestingModule } from '@nestjs/testing';
import { SecurityPoliciesController } from './security-policies.controller.js';
import { SecurityPoliciesService } from './security-policies.service.js';
import { SecurityPolicyKeyEnum } from './security-policies.types.js';
import type { AuthUser } from '../../common/interfaces/auth-user.interface.js';

describe('SecurityPoliciesController', () => {
  let controller: SecurityPoliciesController;

  const mockService = {
    getAllPolicies: jest.fn(),
    getPolicyByKey: jest.fn(),
    createPolicy: jest.fn(),
    updatePolicy: jest.fn(),
  };

  const adminUser: AuthUser = {
    id: 'admin-id',
    email: 'admin@example.com',
    name: 'Admin',
    roles: ['ums:admin'],
    orgs: [],
    perms: [],
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [SecurityPoliciesController],
      providers: [
        {
          provide: SecurityPoliciesService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<SecurityPoliciesController>(
      SecurityPoliciesController,
    );
  });

  it('should get all policies', () => {
    mockService.getAllPolicies.mockReturnValue([
      { key: 'accessTokenTtlSeconds', value: 900 },
    ]);

    const result = controller.getAllPolicies();
    expect(result).toEqual([{ key: 'accessTokenTtlSeconds', value: 900 }]);
    expect(mockService.getAllPolicies).toHaveBeenCalled();
  });

  it('should get single policy by key', async () => {
    mockService.getPolicyByKey.mockResolvedValue({
      key: 'maxActiveSessionsPerUser',
      value: 5,
    });

    const result = await controller.getPolicyByKey('maxActiveSessionsPerUser');
    expect(result).toEqual({ key: 'maxActiveSessionsPerUser', value: 5 });
    expect(mockService.getPolicyByKey).toHaveBeenCalledWith(
      'maxActiveSessionsPerUser',
    );
  });

  it('should update policy with admin user id', async () => {
    mockService.updatePolicy.mockResolvedValue({
      key: 'enforceMfa',
      value: true,
      updatedBy: 'admin-id',
    });

    const result = await controller.updatePolicy(
      'enforceMfa',
      { value: true },
      adminUser,
    );

    expect(result.updatedBy).toBe('admin-id');
    expect(mockService.updatePolicy).toHaveBeenCalledWith(
      'enforceMfa',
      { value: true },
      'admin-id',
    );
  });

  it('should create policy with admin user id', async () => {
    mockService.createPolicy.mockResolvedValue({
      key: SecurityPolicyKeyEnum.AccessTokenTtlSeconds,
      value: 1200,
      updatedBy: 'admin-id',
    });

    const result = await controller.createPolicy(
      { key: SecurityPolicyKeyEnum.AccessTokenTtlSeconds, value: 1200 },
      adminUser,
    );

    expect(result.updatedBy).toBe('admin-id');
    expect(mockService.createPolicy).toHaveBeenCalledWith(
      { key: SecurityPolicyKeyEnum.AccessTokenTtlSeconds, value: 1200 },
      'admin-id',
    );
  });
});
