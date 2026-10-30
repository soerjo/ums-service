import { Test, TestingModule } from '@nestjs/testing';
import { DomainsService } from './domains.service.js';
import { DomainsRepository } from './domains.repository.js';
import { CreateDomainDto } from './dto/create-domain.dto.js';
import { UpdateDomainDto } from './dto/update-domain.dto.js';

jest.mock('../../common/utils/password.util.js', () => ({
  hashPassword: jest.fn().mockResolvedValue('mocked_argon2_hash'),
}));

import { hashPassword } from '../../common/utils/password.util.js';

describe('DomainsService', () => {
  let service: DomainsService;
  let repository: {
    createWithAdmin: jest.Mock;
    findAll: jest.Mock;
    findById: jest.Mock;
    findByOrigin: jest.Mock;
    findByApiKey: jest.Mock;
    update: jest.Mock;
    delete: jest.Mock;
  };

  const mockDomain = {
    id: 'domain-uuid-1',
    name: 'Pesanggrahan',
    origin: 'https://pesanggrahan.example.com',
    apiKey: 'dom_live_secret123',
    isActive: true,
    createdAt: new Date('2026-01-01'),
    updatedAt: new Date('2026-01-01'),
  };

  const mockAdminUser = {
    id: 'user-uuid-1',
    email: 'admin@pesanggrahan.example.com',
    name: 'Domain Admin',
    domainId: 'domain-uuid-1',
    status: 'ACTIVE',
    createdAt: new Date('2026-01-01'),
    updatedAt: new Date('2026-01-01'),
  };

  beforeEach(async () => {
    repository = {
      createWithAdmin: jest.fn(),
      findAll: jest.fn(),
      findById: jest.fn(),
      findByOrigin: jest.fn(),
      findByApiKey: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DomainsService,
        {
          provide: DomainsRepository,
          useValue: repository,
        },
      ],
    }).compile();

    service = module.get<DomainsService>(DomainsService);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('hashes password and calls repository.createWithAdmin', async () => {
      const dto: CreateDomainDto = {
        name: 'Pesanggrahan',
        origin: 'https://pesanggrahan.example.com',
        apiKey: 'dom_live_secret123',
        adminEmail: 'admin@pesanggrahan.example.com',
        adminPassword: 'Password123!',
        adminName: 'Domain Admin',
      };

      const expectedResult = {
        domain: mockDomain,
        admin: mockAdminUser,
      };

      repository.createWithAdmin.mockResolvedValue(expectedResult);

      const result = await service.create(dto);

      expect(hashPassword).toHaveBeenCalledWith('Password123!');
      expect(repository.createWithAdmin).toHaveBeenCalledWith(
        {
          name: dto.name,
          origin: dto.origin,
          apiKey: dto.apiKey,
        },
        {
          email: dto.adminEmail,
          passwordHash: 'mocked_argon2_hash',
          name: dto.adminName,
        },
      );
      expect(result).toEqual(expectedResult);
    });
  });

  describe('findAll', () => {
    it('returns an array of domains', async () => {
      repository.findAll.mockResolvedValue([mockDomain]);

      const result = await service.findAll();

      expect(repository.findAll).toHaveBeenCalled();
      expect(result).toEqual([mockDomain]);
    });
  });

  describe('findById', () => {
    it('returns a domain by id', async () => {
      repository.findById.mockResolvedValue(mockDomain);

      const result = await service.findById('domain-uuid-1');

      expect(repository.findById).toHaveBeenCalledWith('domain-uuid-1');
      expect(result).toEqual(mockDomain);
    });
  });

  describe('findByOrigin', () => {
    it('returns a domain by origin', async () => {
      repository.findByOrigin.mockResolvedValue(mockDomain);

      const result = await service.findByOrigin(
        'https://pesanggrahan.example.com',
      );

      expect(repository.findByOrigin).toHaveBeenCalledWith(
        'https://pesanggrahan.example.com',
      );
      expect(result).toEqual(mockDomain);
    });
  });

  describe('findByApiKey', () => {
    it('returns a domain by apiKey', async () => {
      repository.findByApiKey.mockResolvedValue(mockDomain);

      const result = await service.findByApiKey('dom_live_secret123');

      expect(repository.findByApiKey).toHaveBeenCalledWith(
        'dom_live_secret123',
      );
      expect(result).toEqual(mockDomain);
    });
  });

  describe('update', () => {
    it('calls repository.update with id and dto', async () => {
      const dto: UpdateDomainDto = {
        name: 'Updated Name',
        isActive: false,
      };
      const updatedDomain = { ...mockDomain, ...dto };
      repository.update.mockResolvedValue(updatedDomain);

      const result = await service.update('domain-uuid-1', dto);

      expect(repository.update).toHaveBeenCalledWith('domain-uuid-1', dto);
      expect(result).toEqual(updatedDomain);
    });
  });

  describe('delete', () => {
    it('calls repository.delete with id', async () => {
      repository.delete.mockResolvedValue(mockDomain);

      const result = await service.delete('domain-uuid-1');

      expect(repository.delete).toHaveBeenCalledWith('domain-uuid-1');
      expect(result).toEqual(mockDomain);
    });
  });
});
