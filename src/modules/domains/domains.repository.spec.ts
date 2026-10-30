import { NotFoundException } from '@nestjs/common';
import { UserStatus } from '@prisma/client';
import { DomainsRepository } from './domains.repository.js';
import type { PrismaService } from '../../prisma/prisma.service.js';

describe('DomainsRepository', () => {
  let repository: DomainsRepository;
  let mockDomainCreate: jest.Mock;
  let mockRoleUpsert: jest.Mock;
  let mockUserCreate: jest.Mock;
  let mockUserRoleCreate: jest.Mock;
  let mockDomainFindMany: jest.Mock;
  let mockDomainFindUnique: jest.Mock;
  let mockDomainUpdate: jest.Mock;
  let mockDomainDelete: jest.Mock;
  let mockTransaction: jest.Mock;

  beforeEach(() => {
    mockDomainCreate = jest.fn().mockResolvedValue({
      id: 'dom-1',
      name: 'App 1',
      origin: 'https://app1.test',
      apiKey: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    mockRoleUpsert = jest.fn().mockResolvedValue({
      id: 'role-domain-admin',
      name: 'domain:admin',
      description: 'Domain administrator',
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    mockUserCreate = jest.fn().mockResolvedValue({
      id: 'user-1',
      email: 'admin@app1.test',
      name: 'Admin 1',
      passwordHash: 'hashed',
      domainId: 'dom-1',
      status: UserStatus.ACTIVE,
      emailVerifiedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    mockUserRoleCreate = jest.fn().mockResolvedValue({
      userId: 'user-1',
      roleId: 'role-domain-admin',
      assignedAt: new Date(),
    });

    mockTransaction = jest
      .fn()
      .mockImplementation((cb: (tx: unknown) => Promise<unknown>) => {
        const tx = {
          domain: { create: mockDomainCreate },
          role: { upsert: mockRoleUpsert },
          user: { create: mockUserCreate },
          userRole: { create: mockUserRoleCreate },
        };
        return cb(tx);
      });

    mockDomainFindMany = jest.fn().mockResolvedValue([{ id: 'dom-1' }]);
    mockDomainFindUnique = jest.fn();
    mockDomainUpdate = jest.fn();
    mockDomainDelete = jest.fn();

    const prisma = {
      $transaction: mockTransaction,
      domain: {
        findMany: mockDomainFindMany,
        findUnique: mockDomainFindUnique,
        update: mockDomainUpdate,
        delete: mockDomainDelete,
      },
    };

    repository = new DomainsRepository(prisma as unknown as PrismaService);
  });

  describe('createWithAdmin', () => {
    it('creates domain and admin user inside a transaction', async () => {
      const res = await repository.createWithAdmin(
        { name: 'App 1', origin: 'https://app1.test' },
        { email: 'admin@app1.test', passwordHash: 'hashed', name: 'Admin 1' },
      );

      expect(res.domain.id).toBe('dom-1');
      expect(res.admin.id).toBe('user-1');
      expect(res.admin.passwordHash).toBeUndefined();
    });
  });

  describe('findAll', () => {
    it('returns all domains ordered by createdAt desc', async () => {
      const res = await repository.findAll();
      expect(res).toEqual([{ id: 'dom-1' }]);
      expect(mockDomainFindMany).toHaveBeenCalledWith({
        orderBy: { createdAt: 'desc' },
      });
    });
  });

  describe('findById', () => {
    it('returns domain if found', async () => {
      mockDomainFindUnique.mockResolvedValue({ id: 'dom-1' });
      const res = await repository.findById('dom-1');
      expect(res).toEqual({ id: 'dom-1' });
    });

    it('throws NotFoundException if domain not found', async () => {
      mockDomainFindUnique.mockResolvedValue(null);
      await expect(repository.findById('dom-99')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('findByOrigin', () => {
    it('queries by origin', async () => {
      mockDomainFindUnique.mockResolvedValue({
        id: 'dom-1',
        origin: 'https://app1.test',
      });
      const res = await repository.findByOrigin('https://app1.test');
      expect(res).toEqual({ id: 'dom-1', origin: 'https://app1.test' });
    });
  });

  describe('findByApiKey', () => {
    it('queries by apiKey', async () => {
      mockDomainFindUnique.mockResolvedValue({
        id: 'dom-1',
        apiKey: 'key-123',
      });
      const res = await repository.findByApiKey('key-123');
      expect(res).toEqual({ id: 'dom-1', apiKey: 'key-123' });
    });
  });

  describe('update', () => {
    it('verifies domain exists and updates it', async () => {
      mockDomainFindUnique.mockResolvedValue({ id: 'dom-1' });
      mockDomainUpdate.mockResolvedValue({ id: 'dom-1', name: 'Updated' });
      const res = await repository.update('dom-1', { name: 'Updated' });
      expect(res.name).toBe('Updated');
    });
  });

  describe('delete', () => {
    it('verifies domain exists and deletes it', async () => {
      mockDomainFindUnique.mockResolvedValue({ id: 'dom-1' });
      mockDomainDelete.mockResolvedValue({ id: 'dom-1' });
      const res = await repository.delete('dom-1');
      expect(res).toEqual({ id: 'dom-1' });
    });
  });
});
