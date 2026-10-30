import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { PermissionsService } from './permissions.service.js';
import { CreatePermissionDto } from './dto/create-permission.dto.js';
import { UpdatePermissionDto } from './dto/update-permission.dto.js';
import { RegisterPermissionsDto } from './dto/register-permissions.dto.js';
import { Roles } from '../../common/decorators/roles.decorator.js';
import { UMS_ADMIN_ROLE } from '../auth/auth.constants.js';

@ApiTags('Permissions')
@ApiBearerAuth()
@Roles(UMS_ADMIN_ROLE)
@Controller('permissions')
export class PermissionsController {
  constructor(private readonly permissionsService: PermissionsService) {}

  @Get()
  @ApiOperation({ summary: 'List all permissions' })
  async findAll() {
    return this.permissionsService.findAll();
  }

  @Post()
  @ApiOperation({ summary: 'Create a new permission' })
  async create(@Body() dto: CreatePermissionDto) {
    return this.permissionsService.create(dto);
  }

  @Post('register')
  @ApiOperation({
    summary: 'Bulk register permission manifest for downstream services',
  })
  async registerManifest(@Body() dto: RegisterPermissionsDto) {
    return this.permissionsService.registerManifest(dto);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get permission by ID' })
  async findOne(@Param('id') id: string) {
    return this.permissionsService.findById(id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update permission details' })
  async update(@Param('id') id: string, @Body() dto: UpdatePermissionDto) {
    return this.permissionsService.update(id, dto);
  }

  @Delete(':id')
  @ApiOperation({
    summary: 'Delete a permission (protected if assigned to any role)',
  })
  async remove(@Param('id') id: string) {
    return this.permissionsService.remove(id);
  }
}
