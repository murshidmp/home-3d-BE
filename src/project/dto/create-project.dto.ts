// src/project/dto/create-project.dto.ts

import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateProjectDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  // This part is missing in your original DTO:
  @IsNotEmpty()
  // If you know the shape, you can define a more specific type or use Record<string, any>
  projectData: any;
}
