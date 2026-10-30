import { Injectable } from '@nestjs/common';
import { PermissionsRepository } from './permissions.repository.js';
import { CreatePermissionDto } from './dto/create-permission.dto.js';
import { UpdatePermissionDto } from './dto/update-permission.dto.js';
import {
  RegisterPermissionsDto,
  RegisterPermissionsResult,
} from './dto/register-permissions.dto.js';
import { AuditService } from '../audit/audit.service.js';

@Injectable()
export class PermissionsService {
  constructor(
    private readonly permissionsRepository: PermissionsRepository,
    private readonly auditService: AuditService,
  ) {}

  async findAll() {
    return this.permissionsRepository.findAll();
  }

  async findById(id: string) {
    return this.permissionsRepository.findById(id);
  }

  async create(dto: CreatePermissionDto) {
    const permission = await this.permissionsRepository.create(dto);
    await this.auditService.log({
      action: 'permission.created',
      actorType: 'admin',
      subjectType: 'permission',
      subjectId: permission.id,
      metadata: { name: permission.name },
    });
    return permission;
  }

  async update(id: string, dto: UpdatePermissionDto) {
    const permission = await this.permissionsRepository.update(id, dto);
    await this.auditService.log({
      action: 'permission.updated',
      actorType: 'admin',
      subjectType: 'permission',
      subjectId: permission.id,
      metadata: { name: permission.name },
    });
    return permission;
  }

  async remove(id: string) {
    const permission = await this.permissionsRepository.remove(id);
    await this.auditService.log({
      action: 'permission.deleted',
      actorType: 'admin',
      severity: 'warn',
      subjectType: 'permission',
      subjectId: id,
    });
    return permission;
  }

  async registerManifest(
    dto: RegisterPermissionsDto,
  ): Promise<RegisterPermissionsResult> {
    const uniquePermissions = Array.from(
      new Map(dto.permissions.map((p) => [p.name, p])).values(),
    );

    const upserted =
      await this.permissionsRepository.upsertMany(uniquePermissions);

    const permissions = upserted.map((p) => p.name);

    await this.auditService.log({
      action: 'permission.manifest_registered',
      actorType: 'system',
      subjectType: 'permission_manifest',
      subjectId: dto.serviceName,
      metadata: {
        serviceName: dto.serviceName,
        registeredCount: permissions.length,
        permissions,
      },
    });

    return {
      serviceName: dto.serviceName,
      registeredCount: permissions.length,
      permissions,
    };
  }
}
