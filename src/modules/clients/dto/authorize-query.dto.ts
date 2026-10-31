import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class AuthorizeQueryDto {
  @ApiProperty({ example: 'code' })
  @IsString()
  @IsNotEmpty()
  response_type: string;

  @ApiProperty({ example: 'my-client-id' })
  @IsString()
  @IsNotEmpty()
  client_id: string;

  @ApiProperty({ example: 'https://app.example.com/callback' })
  @IsString()
  @IsNotEmpty()
  redirect_uri: string;

  @ApiPropertyOptional({ example: 'openid profile email' })
  @IsOptional()
  @IsString()
  scope?: string;

  @ApiPropertyOptional({ example: 'random_state_string' })
  @IsOptional()
  @IsString()
  state?: string;

  @ApiPropertyOptional({
    example: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  })
  @IsOptional()
  @IsString()
  code_challenge?: string;

  @ApiPropertyOptional({ example: 'S256' })
  @IsOptional()
  @IsString()
  code_challenge_method?: string;
}
