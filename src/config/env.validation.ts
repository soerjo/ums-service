import { plainToInstance } from 'class-transformer';
import {
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsPort,
  IsString,
  validateSync,
} from 'class-validator';

enum Environment {
  Development = 'development',
  Production = 'production',
  Test = 'test',
}

class EnvironmentVariables {
  @IsEnum(Environment)
  NODE_ENV: Environment = Environment.Development;

  @IsPort()
  @IsOptional()
  PORT: string = '3000';

  @IsString()
  @IsNotEmpty()
  DATABASE_URL!: string;

  @IsString()
  @IsOptional()
  JWT_ACCESS_SECRET?: string;

  @IsString()
  @IsOptional()
  JWT_REFRESH_SECRET?: string;

  @IsString()
  @IsOptional()
  UMS_JWT_PRIVATE_KEY?: string;

  @IsString()
  @IsOptional()
  UMS_JWT_PRIVATE_KEY_PATH?: string;

  @IsString()
  @IsOptional()
  JWT_ACCESS_EXPIRATION: string = '15m';

  @IsString()
  @IsOptional()
  JWT_REFRESH_EXPIRATION: string = '7d';

  @IsString()
  @IsOptional()
  GOOGLE_CLIENT_ID?: string;

  @IsString()
  @IsOptional()
  GOOGLE_CLIENT_SECRET?: string;

  @IsString()
  @IsOptional()
  GOOGLE_CALLBACK_URL: string =
    'http://localhost:3000/api/auth/google/callback';

  @IsString()
  @IsOptional()
  FRONTEND_URL: string = 'http://localhost:5173';

  @IsString()
  @IsOptional()
  CORS_ORIGINS?: string;

  @IsString()
  @IsOptional()
  COOKIE_SECURE?: string;

  @IsNumber()
  @IsOptional()
  THROTTLE_TTL_MS: number = 60000;

  @IsNumber()
  @IsOptional()
  THROTTLE_LIMIT: number = 10;

  @IsString()
  @IsOptional()
  UMS_ADMIN_EMAIL?: string;

  @IsString()
  @IsOptional()
  UMS_ADMIN_PASSWORD?: string;

  @IsString()
  @IsOptional()
  UMS_ADMIN_NAME?: string;

  @IsNumber()
  @IsOptional()
  AUTH_TOKEN_TTL_MINUTES: number = 60;

  @IsNumber()
  @IsOptional()
  AUTH_TOKEN_TTL_HOURS: number = 24;

  // Mail (ADR 0004): 'log' = dev (no network), 'smtp' = real delivery.
  @IsString()
  @IsOptional()
  APP_ENCRYPTION_KEY?: string;

  @IsString()
  @IsOptional()
  MAIL_TRANSPORT: string = 'log';

  @IsString()
  @IsOptional()
  SMTP_HOST?: string;

  @IsString()
  @IsOptional()
  SMTP_PORT?: string;

  @IsString()
  @IsOptional()
  SMTP_SECURE?: string;

  @IsString()
  @IsOptional()
  SMTP_USER?: string;

  @IsString()
  @IsOptional()
  SMTP_PASSWORD?: string;

  @IsString()
  @IsOptional()
  MAIL_FROM?: string;

  @IsString()
  @IsOptional()
  APP_WEB_URL: string = 'http://localhost:5173';

  // Optional: when set, log-transport messages are appended as one JSON line
  // per message to this file (dev/test capture; production leaves it unset).
  @IsString()
  @IsOptional()
  MAIL_LOG_FILE?: string;

  @IsString()
  @IsOptional()
  KAFKA_BROKERS?: string;

  @IsString()
  @IsOptional()
  KAFKA_PRODUCER_DISABLED?: string;

  @IsString()
  @IsOptional()
  KAFKA_CLIENT_ID?: string;
}

export function validate(config: Record<string, unknown>) {
  const validated = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });
  const errors = validateSync(validated, { skipMissingProperties: false });

  if (errors.length > 0) {
    throw new Error(errors.toString());
  }

  if (
    !validated.UMS_JWT_PRIVATE_KEY?.trim() &&
    !validated.UMS_JWT_PRIVATE_KEY_PATH?.trim()
  ) {
    throw new Error(
      'Environment validation failed: RS256 JWT signing requires one of ' +
        'UMS_JWT_PRIVATE_KEY (inline PEM) or UMS_JWT_PRIVATE_KEY_PATH (path to a PEM file).',
    );
  }

  return validated;
}
