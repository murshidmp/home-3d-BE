import { ApiProperty } from '@nestjs/swagger';
import { Expose, Type } from 'class-transformer';
import { UserResponseDto } from 'src/common/dto/user-response.dto';
import { ProjectResponseDto } from 'src/project/dto/project-response.dto';

export class PostResponseDto {
  @Expose()
  id: number;

  @Expose()
  imageUrl: string;

  @Expose()
  description?: string;

  @Expose()
  likeCount: number;

  @Expose()
  commentCount: number;

  @Expose()
  isTrending: boolean;

  @Expose()
  createdAt: Date;

  @Expose()
  updatedAt: Date;

  @Expose()
  @Type(() => UserResponseDto)
  user: UserResponseDto;

  @Expose()
  @Type(() => ProjectResponseDto)
  project?: ProjectResponseDto;
}