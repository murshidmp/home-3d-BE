import { IsNotEmpty, IsOptional, IsString, IsInt } from 'class-validator';

export class CreatePostDto {
  @IsNotEmpty()
  @IsString()
  imageUrl: string;

  @IsOptional()
  @IsString()
  description?: string;

  // If the post is linked to a project, its ID is a number (auto-incremented)
  @IsOptional()
  @IsInt()
  projectId?: number;
}
