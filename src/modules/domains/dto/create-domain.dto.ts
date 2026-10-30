import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  MinLength,
} from 'class-validator';

export class CreateDomainDto {
  @ApiProperty({
    description: 'Name of the domain/tenant',
    example: 'Pesanggrahan Branch',
  })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({
    description: 'Origin URL or hostname of the domain',
    example: 'https://pesanggrahan.example.com',
  })
  @IsString()
  @IsNotEmpty()
  origin: string;

  @ApiPropertyOptional({
    description: 'Optional API key for domain authentication',
    example: 'dom_live_secret123',
  })
  @IsString()
  @IsOptional()
  apiKey?: string;

  @ApiProperty({
    description: 'Email address of the initial domain administrator',
    example: 'admin@pesanggrahan.example.com',
  })
  @IsEmail()
  adminEmail: string;

  @ApiProperty({
    description: 'Password for the initial domain administrator',
    example: 'SuperSecret123!',
    minLength: 8,
  })
  @IsString()
  @MinLength(8)
  adminPassword: string;

  @ApiPropertyOptional({
    description: 'Full name of the initial domain administrator',
    example: 'Domain Admin',
  })
  @IsString()
  @IsOptional()
  adminName?: string;
}
