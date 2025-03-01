import { ApiProperty } from "@nestjs/swagger";
import { IsDate, IsEmail, IsNotEmpty, IsString, MaxLength, MinLength } from "class-validator";

export class CreateUserDto {
  
    @ApiProperty()
    @IsNotEmpty()
    @IsString()
    @MaxLength(12)
    username: string;
  
    @ApiProperty()
    @IsNotEmpty()
    // @IsDate()
    dob: Date;
  
    @ApiProperty()
    @IsNotEmpty()
    @IsString()
    gender?: string;
   
    @ApiProperty()
    @IsNotEmpty()
    @IsEmail()
    email: string;

    @ApiProperty()
    @IsString()
    @MinLength(8)
    @MaxLength(20)
    password: string;
  }