import { ApiPropertyOptional, OmitType, PartialType } from '@nestjs/swagger';
import { IsBoolean, IsOptional } from 'class-validator';
import { CreateDomainDto } from './create-domain.dto.js';

export class UpdateDomainDto extends PartialType(
  OmitType(CreateDomainDto, [
    'adminEmail',
    'adminPassword',
    'adminName',
  ] as const),
) {
  @ApiPropertyOptional({
    description: 'Whether the domain is active',
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}
