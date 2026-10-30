import { Test, TestingModule } from '@nestjs/testing';
import { DomainsController } from './domains.controller.js';
import { DomainsService } from './domains.service.js';
import { CreateDomainDto } from './dto/create-domain.dto.js';
import { UpdateDomainDto } from './dto/update-domain.dto.js';

describe('DomainsController', () => {
  let controller: DomainsController;
  let domainsService: {
    create: jest.Mock;
    findAll: jest.Mock;
    findById: jest.Mock;
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

  beforeEach(async () => {
    domainsService = {
      create: jest.fn(),
      findAll: jest.fn(),
      findById: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [DomainsController],
      providers: [
        {
          provide: DomainsService,
          useValue: domainsService,
        },
      ],
    }).compile();

    controller = module.get<DomainsController>(DomainsController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('create', () => {
    it('should create a domain and return the result', async () => {
      const dto: CreateDomainDto = {
        name: 'Pesanggrahan',
        origin: 'https://pesanggrahan.example.com',
        apiKey: 'dom_live_secret123',
        adminEmail: 'admin@pesanggrahan.example.com',
        adminPassword: 'SuperSecret123!',
        adminName: 'Domain Admin',
      };
      const expected = { ...mockDomain };
      domainsService.create.mockResolvedValue(expected);

      const result = await controller.create(dto);

      expect(result).toEqual(expected);
      expect(domainsService.create).toHaveBeenCalledTimes(1);
      expect(domainsService.create).toHaveBeenCalledWith(dto);
    });
  });

  describe('findAll', () => {
    it('should return all domains', async () => {
      const expected = [mockDomain];
      domainsService.findAll.mockResolvedValue(expected);

      const result = await controller.findAll();

      expect(result).toEqual(expected);
      expect(domainsService.findAll).toHaveBeenCalledTimes(1);
      expect(domainsService.findAll).toHaveBeenCalledWith();
    });
  });

  describe('findOne', () => {
    it('should return a domain by ID', async () => {
      domainsService.findById.mockResolvedValue(mockDomain);

      const result = await controller.findOne('domain-uuid-1');

      expect(result).toEqual(mockDomain);
      expect(domainsService.findById).toHaveBeenCalledTimes(1);
      expect(domainsService.findById).toHaveBeenCalledWith('domain-uuid-1');
    });
  });

  describe('update', () => {
    it('should update a domain and return the updated entity', async () => {
      const dto: UpdateDomainDto = {
        name: 'Pesanggrahan Updated',
        isActive: false,
      };
      const expected = { ...mockDomain, ...dto };
      domainsService.update.mockResolvedValue(expected);

      const result = await controller.update('domain-uuid-1', dto);

      expect(result).toEqual(expected);
      expect(domainsService.update).toHaveBeenCalledTimes(1);
      expect(domainsService.update).toHaveBeenCalledWith('domain-uuid-1', dto);
    });
  });

  describe('remove', () => {
    it('should delete a domain and return the deleted entity', async () => {
      domainsService.delete.mockResolvedValue(mockDomain);

      const result = await controller.remove('domain-uuid-1');

      expect(result).toEqual(mockDomain);
      expect(domainsService.delete).toHaveBeenCalledTimes(1);
      expect(domainsService.delete).toHaveBeenCalledWith('domain-uuid-1');
    });
  });
});
