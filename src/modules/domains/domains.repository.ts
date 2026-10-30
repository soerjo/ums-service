import { Injectable, NotFoundException } from '@nestjs/common';
import { UserStatus } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service.js';

export interface CreateDomainData {
  name: string;
  origin: string;
  apiKey?: string;
}

export interface CreateAdminUserData {
  email: string;
  passwordHash: string;
  name?: string;
}

export interface UpdateDomainData {
  name?: string;
  origin?: string;
  apiKey?: string;
  isActive?: boolean;
}

@Injectable()
export class DomainsRepository {
  constructor(private readonly prisma: PrismaService) {}

  async createWithAdmin(
    domainData: CreateDomainData,
    adminUserData: CreateAdminUserData,
    adminRoleName = 'domain:admin',
  ) {
    return this.prisma.$transaction(async (tx) => {
      // a. Buat Domain
      const domain = await tx.domain.create({
        data: {
          name: domainData.name,
          origin: domainData.origin,
          apiKey: domainData.apiKey,
        },
      });

      // b. Pastikan Role 'domain:admin' ada (upsert jika belum ada)
      const role = await tx.role.upsert({
        where: { name: adminRoleName },
        update: {},
        create: {
          name: adminRoleName,
          description: 'Domain administrator',
        },
      });

      // c. Buat User dengan email, passwordHash, name, domainId: domain.id, status: ACTIVE
      const user = await tx.user.create({
        data: {
          email: adminUserData.email,
          passwordHash: adminUserData.passwordHash,
          name: adminUserData.name ?? null,
          domainId: domain.id,
          status: UserStatus.ACTIVE,
        },
      });

      // d. Hubungkan User ke Role 'domain:admin' (UserRole)
      await tx.userRole.create({
        data: {
          userId: user.id,
          roleId: role.id,
        },
      });

      // e. Return domain dan admin user (tanpa passwordHash)
      const admin: Record<string, unknown> = { ...user };
      delete admin.passwordHash;
      return {
        domain,
        admin,
      };
    });
  }

  async findAll() {
    return this.prisma.domain.findMany({
      orderBy: { createdAt: 'desc' },
    });
  }

  async findById(id: string) {
    const domain = await this.prisma.domain.findUnique({
      where: { id },
    });
    if (!domain) {
      throw new NotFoundException(`Domain with id ${id} not found`);
    }
    return domain;
  }

  async findByOrigin(origin: string) {
    return this.prisma.domain.findUnique({
      where: { origin },
    });
  }

  async findByApiKey(apiKey: string) {
    return this.prisma.domain.findUnique({
      where: { apiKey },
    });
  }

  async update(id: string, data: UpdateDomainData) {
    await this.findById(id);
    return this.prisma.domain.update({
      where: { id },
      data,
    });
  }

  async delete(id: string) {
    await this.findById(id);
    return this.prisma.domain.delete({
      where: { id },
    });
  }
}
