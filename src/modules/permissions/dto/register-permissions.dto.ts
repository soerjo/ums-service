import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  ValidateNested,
} from 'class-validator';

export class RegisterPermissionItemDto {
  @ApiProperty({
    example: 'order:read',
    description: "Permission name in 'resource:action' format",
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+$/, {
    message: "name must follow the 'resource:action' format (e.g. order:read)",
  })
  name!: string;

  @ApiPropertyOptional({
    example: 'Can read order details and listing',
    description: 'Optional description of the permission',
  })
  @IsString()
  @IsOptional()
  description?: string;
}

export class RegisterPermissionsDto {
  @ApiProperty({
    example: 'pos-service',
    description: 'Name of the service registering permissions',
  })
  @IsString()
  @IsNotEmpty()
  serviceName!: string;

  @ApiProperty({
    type: [RegisterPermissionItemDto],
    description: 'List of permissions defined by the service',
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RegisterPermissionItemDto)
  permissions!: RegisterPermissionItemDto[];
}

export interface RegisterPermissionsResult {
  serviceName: string;
  registeredCount: number;
  permissions: string[];
}
