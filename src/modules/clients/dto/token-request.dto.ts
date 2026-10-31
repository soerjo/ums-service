import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class TokenRequestDto {
  @ApiProperty({ example: 'authorization_code' })
  @IsString()
  @IsNotEmpty()
  grant_type: string;

  @ApiPropertyOptional({ example: 'my-client-id' })
  @IsOptional()
  @IsString()
  client_id?: string;

  @ApiPropertyOptional({ example: 'secret' })
  @IsOptional()
  @IsString()
  client_secret?: string;

  @ApiPropertyOptional({ example: 'AUTH_CODE_XYZ' })
  @IsOptional()
  @IsString()
  code?: string;

  @ApiPropertyOptional({ example: 'https://app.example.com/callback' })
  @IsOptional()
  @IsString()
  redirect_uri?: string;

  @ApiPropertyOptional({
    example: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
  })
  @IsOptional()
  @IsString()
  code_verifier?: string;
}
