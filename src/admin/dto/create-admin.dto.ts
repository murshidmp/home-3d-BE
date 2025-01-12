import {
    IsString, MinLength, MaxLength, IsEnum, IsOptional
  } from 'class-validator';
  import { AdminStatus } from '../entities/admin.entity';
  import { Role } from 'src/common/enums/roles';
  import { ApiProperty } from '@nestjs/swagger';
  
  
  export class CreateAdminDto {
    @ApiProperty()
    @IsString()
    name: string;
  
    @ApiProperty()
    @IsString()
    authority_type: Role;
  
    @ApiProperty()
    @IsString()
    email: string;
  
    @ApiProperty()
    @IsEnum(AdminStatus)
    status: AdminStatus;
  
    @ApiProperty()
    @IsString()
    password: string;
  
    @IsOptional()
    @IsString()
    refreshToken?: string;
  }
  