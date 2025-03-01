import { IsString, IsNotEmpty, Length } from 'class-validator';
export class ChangeEmailDto {
  @IsString()
  @IsNotEmpty()
  currentEmail: string;

  @IsString()
  @IsNotEmpty()
  newEmail: string;
}
