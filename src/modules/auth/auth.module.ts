import { Module, forwardRef } from '@nestjs/common';
import { ClientsModule } from '../clients/clients.module.js';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service.js';
import { AuthController } from './auth.controller.js';
import { JwksController } from './jwks.controller.js';
import { JwtKeysService } from './jwt-keys.service.js';
import { LocalStrategy } from './strategies/local.strategy.js';
import { JwtStrategy } from './strategies/jwt.strategy.js';
import { UsersModule } from '../users/users.module.js';
import { parseDurationToSeconds } from '../../common/utils/token-expiry.util.js';
import { loadJwtRsaKeypair } from '../../common/utils/jwt-keypair.util.js';
import { computeKeyId } from '../../common/utils/jwk.util.js';
import { AuthTokensRepository } from './auth-tokens.repository.js';
import { MailModule } from '../mail/mail.module.js';
import { AuditModule } from '../audit/audit.module.js';
import { MfaModule } from '../mfa/mfa.module.js';
import { SecurityPoliciesModule } from '../security-policies/security-policies.module.js';
import { JWT_ISSUER } from './auth.constants.js';
import type { JwtModuleOptions } from '@nestjs/jwt';

@Module({
  imports: [
    PassportModule,
    forwardRef(() => ClientsModule),
    UsersModule,
    MailModule,
    AuditModule,
    forwardRef(() => MfaModule),
    SecurityPoliciesModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService): JwtModuleOptions => {
        const { privateKey, publicKey } = loadJwtRsaKeypair({
          privateKey: configService.get<string>('UMS_JWT_PRIVATE_KEY'),
          privateKeyPath: configService.get<string>('UMS_JWT_PRIVATE_KEY_PATH'),
        });

        return {
          privateKey,
          signOptions: {
            algorithm: 'RS256',
            expiresIn: parseDurationToSeconds(
              configService.get<string>('JWT_ACCESS_EXPIRATION') ?? '15m',
            ), // in seconds
            issuer: JWT_ISSUER,
            keyid: computeKeyId(publicKey),
          },
        };
      },
    }),
  ],
  controllers: [AuthController, JwksController],
  providers: [
    AuthService,
    AuthTokensRepository,
    JwtKeysService,
    LocalStrategy,
    JwtStrategy,
  ],
  exports: [AuthService, AuthTokensRepository, JwtKeysService],
})
export class AuthModule {}
