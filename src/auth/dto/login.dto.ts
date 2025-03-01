import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, MaxLength, MinLength, IsString , IsEmail} from 'class-validator';

export class AuthDto {
  @ApiProperty()
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty()
  @IsString()
  @MinLength(8)
  password: string;
}
