import { Injectable } from '@nestjs/common';
import { UsersRepository } from './users.repository.js';
import { AssignRolesDto } from './dto/assign-roles.dto.js';
import { ListUsersDto } from './dto/list-users.dto.js';
import { UpdateUserDto } from './dto/update-user.dto.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import { $Enums } from '@prisma/client';

@Injectable()
export class UsersService {
  constructor(
    private usersRepository: UsersRepository,
    private prisma: PrismaService,
  ) {}

  async findAll(query: ListUsersDto) {
    const page = query.page ?? 1;
    const limit = query.limit ?? 20;
    const { data, total } = await this.usersRepository.findAll({
      skip: (page - 1) * limit,
      take: limit,
    });

    return {
      data: data.map((user) => this.toPublic(user)),
      meta: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async findById(id: string) {
    return this.toPublic(await this.usersRepository.findByIdDetailed(id));
  }

  async update(id: string, dto: UpdateUserDto) {
    await this.usersRepository.update(id, dto);
    if (dto.status === $Enums.UserStatus.BLOCKED) {
      await this.prisma.session.updateMany({
        where: { userId: id, revokedAt: null },
        data: { revokedAt: new Date() },
      });
    }
    return this.findById(id);
  }

  async assignRoles(id: string, dto: AssignRolesDto) {
    return this.toPublic(await this.usersRepository.assignRoles(id, dto.roles));
  }

  private toPublic(
    user: Awaited<ReturnType<UsersRepository['findByIdDetailed']>>,
  ) {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      status: user.status,
      emailVerifiedAt: user.emailVerifiedAt,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      roles: user.userRoles.map((userRole) => userRole.role.name),
      orgs: user.orgMembers.map((member) => ({
        id: member.organization.id,
        name: member.organization.name,
        role: member.role,
      })),
    };
  }
}
