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
import { DomainsService } from './domains.service.js';
import { CreateDomainDto } from './dto/create-domain.dto.js';
import { UpdateDomainDto } from './dto/update-domain.dto.js';
import { Roles } from '../../common/decorators/roles.decorator.js';
import { UMS_ADMIN_ROLE } from '../auth/auth.constants.js';

@ApiTags('Domains')
@ApiBearerAuth()
@Roles(UMS_ADMIN_ROLE)
@Controller('domains')
export class DomainsController {
  constructor(private readonly domainsService: DomainsService) {}

  @Post()
  @ApiOperation({ summary: 'Create a domain and its initial administrator' })
  async create(@Body() dto: CreateDomainDto) {
    return this.domainsService.create(dto);
  }

  @Get()
  @ApiOperation({ summary: 'List all domains' })
  async findAll() {
    return this.domainsService.findAll();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a domain by ID' })
  async findOne(@Param('id') id: string) {
    return this.domainsService.findById(id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a domain' })
  async update(@Param('id') id: string, @Body() dto: UpdateDomainDto) {
    return this.domainsService.update(id, dto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a domain' })
  async remove(@Param('id') id: string) {
    return this.domainsService.delete(id);
  }
}
