import { Expose } from 'class-transformer';

export class ProjectVersionResponseDto {
  @Expose()
  id: number;

  @Expose()
  versionNumber: number;

  @Expose()
  projectData: any; // Replace 'any' with a specific type if applicable
}