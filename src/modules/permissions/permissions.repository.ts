import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import type { Permission } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service.js';
import { CreatePermissionDto } from './dto/create-permission.dto.js';
import { UpdatePermissionDto } from './dto/update-permission.dto.js';

@Injectable()
export class PermissionsRepository {
  constructor(private prisma: PrismaService) {}

  async findAll() {
    return this.prisma.permission.findMany({
      include: {
        _count: {
          select: { rolePermissions: true },
        },
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findById(id: string) {
    const permission = await this.prisma.permission.findUnique({
      where: { id },
      include: {
        _count: {
          select: { rolePermissions: true },
        },
      },
    });

    if (!permission) {
      throw new NotFoundException(`Permission with id ${id} not found`);
    }

    return permission;
  }

  async create(dto: CreatePermissionDto) {
    const existing = await this.prisma.permission.findUnique({
      where: { name: dto.name },
    });
    if (existing) {
      throw new ConflictException(
        `Permission with name '${dto.name}' already exists`,
      );
    }

    return this.prisma.permission.create({
      data: {
        name: dto.name,
        description: dto.description ?? null,
      },
    });
  }

  async update(id: string, dto: UpdatePermissionDto) {
    await this.findById(id);

    if (dto.name) {
      const existing = await this.prisma.permission.findUnique({
        where: { name: dto.name },
      });
      if (existing && existing.id !== id) {
        throw new ConflictException(
          `Permission with name '${dto.name}' already exists`,
        );
      }
    }

    return this.prisma.permission.update({
      where: { id },
      data: {
        name: dto.name,
        description: dto.description,
      },
    });
  }

  async remove(id: string) {
    const permission = await this.prisma.permission.findUnique({
      where: { id },
      include: { _count: { select: { rolePermissions: true } } },
    });

    if (!permission) {
      throw new NotFoundException(`Permission with id ${id} not found`);
    }

    if (permission._count.rolePermissions > 0) {
      throw new ConflictException(
        `Permission cannot be deleted because it is assigned to ${permission._count.rolePermissions} role(s)`,
      );
    }

    await this.prisma.permission.delete({ where: { id } });
    return { message: 'Permission deleted successfully' };
  }

  async upsertMany(permissions: Array<{ name: string; description?: string }>) {
    if (permissions.length === 0) {
      return [];
    }

    if (typeof this.prisma.$transaction === 'function') {
      return this.prisma.$transaction(
        permissions.map((p) =>
          this.prisma.permission.upsert({
            where: { name: p.name },
            create: {
              name: p.name,
              description: p.description ?? null,
            },
            update: {
              ...(p.description !== undefined
                ? { description: p.description }
                : {}),
            },
          }),
        ),
      );
    }

    const results: Permission[] = [];
    for (const p of permissions) {
      results.push(
        await this.prisma.permission.upsert({
          where: { name: p.name },
          create: {
            name: p.name,
            description: p.description ?? null,
          },
          update: {
            ...(p.description !== undefined
              ? { description: p.description }
              : {}),
          },
        }),
      );
    }
    return results;
  }
}
