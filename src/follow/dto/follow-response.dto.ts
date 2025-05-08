import { Expose, Type } from 'class-transformer';
import { UserResponseDto } from 'src/common/dto/user-response.dto';

export class FollowResponseDto {
  @Expose()
  id: number;

  @Expose()
  @Type(() => UserResponseDto)
  follower: UserResponseDto;

  @Expose()
  @Type(() => UserResponseDto)
  following: UserResponseDto;

  @Expose()
  createdAt: Date;
}