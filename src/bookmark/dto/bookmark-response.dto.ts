import { Expose, Type } from 'class-transformer';
import { UserResponseDto } from 'src/common/dto/user-response.dto';
import { PostResponseDto } from 'src/post/dto/post-response.dto';

export class BookmarkResponseDto {
  @Expose()
  id: number;

  @Expose()
  @Type(() => UserResponseDto)
  user: UserResponseDto;

  @Expose()
  @Type(() => PostResponseDto)
  post: PostResponseDto;

  @Expose()
  createdAt: Date;
}