import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, MaxLength, MinLength, IsString } from 'class-validator';

export class AdminSignInDto {
  @ApiProperty()
  @MinLength(4)
  @MaxLength(50)
  @IsNotEmpty()
  email: string;

  @ApiProperty()
  @IsString()
  // @MinLength(8)
  password: string;
}