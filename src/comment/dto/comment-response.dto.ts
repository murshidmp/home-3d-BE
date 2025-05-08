import { Expose, Type } from 'class-transformer';
import { UserResponseDto } from 'src/common/dto/user-response.dto';

export class CommentResponseDto {
  @Expose()
  id: number;

  @Expose()
  content: string;

  @Expose()
  createdAt: Date;

  @Expose()
  @Type(() => UserResponseDto)
  user: UserResponseDto;
}