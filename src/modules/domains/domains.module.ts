import { Module } from '@nestjs/common';
import { DomainsController } from './domains.controller.js';
import { DomainsService } from './domains.service.js';
import { DomainsRepository } from './domains.repository.js';

@Module({
  controllers: [DomainsController],
  providers: [DomainsService, DomainsRepository],
  exports: [DomainsService, DomainsRepository],
})
export class DomainsModule {}
