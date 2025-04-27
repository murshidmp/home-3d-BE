import { Expose, Type } from 'class-transformer';
import { UserResponseDto } from 'src/common/dto/user-response.dto';
import { ProjectVersionResponseDto } from './project-version-response.dto';

export class ProjectResponseDto {
  @Expose()
  id: number;

  @Expose()
  name: string;

  @Expose()
  description?: string;

  @Expose()
  isRendered: boolean;

  @Expose()
  renderCount: number;

  @Expose()
  @Type(() => ProjectVersionResponseDto)
  currentVersion: ProjectVersionResponseDto;

  @Expose()
  @Type(() => UserResponseDto)
  user: UserResponseDto;

  @Expose()
  @Type(() => ProjectVersionResponseDto)
  versions: ProjectVersionResponseDto[];

  
  createdAt: Date;

  
  updatedAt: Date;
}