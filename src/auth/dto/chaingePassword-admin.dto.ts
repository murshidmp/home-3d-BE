import { IsString, MinLength, MaxLength, IsNotEmpty } from 'class-validator';

export class chaingePassword {
  @IsString()
  @MinLength(6)
  @MaxLength(100)
  @IsNotEmpty()
  oldPassword: string;
  @IsString()
  @MinLength(6)
  @MaxLength(100)
  @IsNotEmpty()
  newPassword: string;
}
