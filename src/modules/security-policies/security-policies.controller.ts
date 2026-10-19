import {
  Controller,
  Get,
  Put,
  Patch,
  Body,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { SecurityPoliciesService } from './security-policies.service.js';
import { Roles } from '../../common/decorators/roles.decorator.js';
import { UMS_ADMIN_ROLE } from '../auth/auth.constants.js';
import {
  CreateSecurityPolicyDto,
  UpdateSecurityPolicyDto,
} from './security-policies.types.js';
import { CurrentUser } from '../../common/decorators/current-user.decorator.js';
import type { AuthUser } from '../../common/interfaces/auth-user.interface.js';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard.js';

@Controller('security-policies')
@UseGuards(JwtAuthGuard) // All endpoints are authenticated by default
export class SecurityPoliciesController {
  constructor(
    private readonly securityPoliciesService: SecurityPoliciesService,
  ) {}

  @Get()
  getAllPolicies() {
    return this.securityPoliciesService.getAllPolicies();
  }

  @Get(':key')
  async getPolicyByKey(@Param('key') key: string) {
    return this.securityPoliciesService.getPolicyByKey(key);
  }

  @Post()
  @Roles(UMS_ADMIN_ROLE)
  async createPolicy(
    @Body() dto: CreateSecurityPolicyDto,
    @CurrentUser() user: AuthUser,
  ) {
    return this.securityPoliciesService.createPolicy(dto, user.id);
  }

  @Put(':key')
  @Roles(UMS_ADMIN_ROLE)
  async updatePolicy(
    @Param('key') key: string,
    @Body() dto: UpdateSecurityPolicyDto,
    @CurrentUser() user: AuthUser,
  ) {
    return this.securityPoliciesService.updatePolicy(key, dto, user.id);
  }

  @Patch(':key')
  @Roles(UMS_ADMIN_ROLE)
  async patchPolicy(
    @Param('key') key: string,
    @Body() dto: UpdateSecurityPolicyDto,
    @CurrentUser() user: AuthUser,
  ) {
    return this.securityPoliciesService.updatePolicy(key, dto, user.id);
  }
}
