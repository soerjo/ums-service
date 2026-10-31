import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsUrl } from 'class-validator';

export class UpdateProfileDto {
  @ApiPropertyOptional({ example: 'Ada Lovelace' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({ example: 'https://minio.soerjo.id/avatars/ada.jpg' })
  @IsOptional()
  @IsUrl()
  avatarUrl?: string;

  @ApiPropertyOptional({ example: '+6281234567890' })
  @IsOptional()
  @IsString()
  phone?: string;
}
