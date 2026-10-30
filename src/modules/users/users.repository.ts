import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Prisma, UserStatus } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service.js';

export const USER_DETAIL_SELECT = {
  id: true,
  email: true,
  name: true,
  status: true,
  emailVerifiedAt: true,
  createdAt: true,
  updatedAt: true,
  userRoles: {
    select: { role: { select: { id: true, name: true } } },
  },
  orgMembers: {
    select: {
      role: true,
      organization: { select: { id: true, name: true } },
    },
  },
} satisfies Prisma.UserSelect;

@Injectable()
export class UsersRepository {
  constructor(private prisma: PrismaService) {}

  async findAll({ skip, take }: { skip: number; take: number }) {
    const [data, total] = await this.prisma.$transaction([
      this.prisma.user.findMany({
        select: USER_DETAIL_SELECT,
        orderBy: { createdAt: 'desc' },
        skip,
        take,
      }),
      this.prisma.user.count(),
    ]);

    return { data, total };
  }

  /** Full row (includes passwordHash) — internal auth use only. */
  async findById(id: string) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with id ${id} not found`);
    }
    return user;
  }

  async findByIdDetailed(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: USER_DETAIL_SELECT,
    });
    if (!user) {
      throw new NotFoundException(`User with id ${id} not found`);
    }
    return user;
  }

  async findByEmail(email: string, domainId?: string | null) {
    if (domainId !== undefined) {
      if (domainId === null) {
        return this.prisma.user.findFirst({ where: { email, domainId: null } });
      }
      return this.prisma.user.findFirst({ where: { email, domainId } });
    }
    return this.prisma.user.findFirst({ where: { email } });
  }

  async findByEmailAndDomain(email: string, domainId: string | null) {
    if (domainId === null) {
      return this.prisma.user.findFirst({ where: { email, domainId: null } });
    }
    return this.prisma.user.findFirst({ where: { email, domainId } });
  }

  async update(id: string, data: { name?: string; status?: UserStatus }) {
    await this.findById(id);
    return this.prisma.user.update({
      where: { id },
      data,
      select: USER_DETAIL_SELECT,
    });
  }

  async assignRoles(userId: string, roleNames: string[]) {
    await this.findById(userId);

    const uniqueNames = [...new Set(roleNames)];
    const roles = await this.prisma.role.findMany({
      where: { name: { in: uniqueNames } },
    });

    const foundNames = roles.map((role) => role.name);
    const missing = uniqueNames.filter((name) => !foundNames.includes(name));
    if (missing.length > 0) {
      throw new BadRequestException(`Unknown roles: ${missing.join(', ')}`);
    }

    await this.prisma.$transaction([
      this.prisma.userRole.deleteMany({ where: { userId } }),
      this.prisma.userRole.createMany({
        data: roles.map((role) => ({ userId, roleId: role.id })),
      }),
    ]);

    return this.findByIdDetailed(userId);
  }
}
