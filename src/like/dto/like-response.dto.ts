import { Expose, Type } from 'class-transformer';
import { UserResponseDto } from 'src/common/dto/user-response.dto';

export class LikeResponseDto {
  @Expose()
  id: number;

  @Expose()
  @Type(() => UserResponseDto)
  user: UserResponseDto;

  @Expose()
  createdAt: Date;
}