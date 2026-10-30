import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { WinstonModule } from 'nest-winston';
import { PrismaModule } from './prisma/prisma.module.js';
import { AuthModule } from './modules/auth/auth.module.js';
import { UsersModule } from './modules/users/users.module.js';
import { OrganizationsModule } from './modules/organizations/organizations.module.js';
import { RolesModule } from './modules/roles/roles.module.js';
import { PermissionsModule } from './modules/permissions/permissions.module.js';
import { AuditModule } from './modules/audit/audit.module.js';
import { HealthModule } from './modules/health/health.module.js';
import { MetricsModule } from './modules/metrics/metrics.module.js';
import { MfaModule } from './modules/mfa/mfa.module.js';
import { SessionsModule } from './modules/sessions/sessions.module.js';
import { ClientsModule } from './modules/clients/clients.module.js';
import { SecurityPoliciesModule } from './modules/security-policies/security-policies.module.js';
import { OutboxModule } from './modules/outbox/outbox.module.js';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard.js';
import { RolesGuard } from './common/guards/roles.guard.js';
import { loggerConfig } from './config/logger.config.js';
import { validate } from './config/env.validation.js';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, validate }),
    WinstonModule.forRoot(loggerConfig),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => [
        {
          ttl: configService.get<number>('THROTTLE_TTL_MS', 60000),
          limit: configService.get<number>('THROTTLE_LIMIT', 10),
        },
      ],
    }),
    PrismaModule,
    AuthModule,
    UsersModule,
    OrganizationsModule,
    RolesModule,
    PermissionsModule,
    SessionsModule,
    AuditModule,
    MfaModule,
    HealthModule,
    MetricsModule,
    ClientsModule,
    SecurityPoliciesModule,
    OutboxModule,
  ],
  providers: [
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
})
export class AppModule {}
