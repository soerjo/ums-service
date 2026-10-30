import { Module } from '@nestjs/common';
import { OutboxService, OutboxRelayService } from './outbox.service.js';
import { PrismaModule } from '../../prisma/prisma.module.js';

@Module({
  imports: [PrismaModule],
  providers: [OutboxService, OutboxRelayService],
  exports: [OutboxService],
})
export class OutboxModule {}
