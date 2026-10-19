import { Module } from '@nestjs/common';
import { SecurityPoliciesService } from './security-policies.service.js';
import { SecurityPoliciesController } from './security-policies.controller.js';
import { PrismaModule } from '../../prisma/prisma.module.js';

@Module({
  imports: [PrismaModule],
  providers: [SecurityPoliciesService],
  controllers: [SecurityPoliciesController],
  exports: [SecurityPoliciesService],
})
export class SecurityPoliciesModule {}
