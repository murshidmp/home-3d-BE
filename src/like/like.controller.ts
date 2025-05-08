import { Controller, Post, Delete, Get, Param, UseGuards, Req } from '@nestjs/common';
import { LikeService } from './like.service';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { ApiTags, ApiBearerAuth, ApiResponse } from '@nestjs/swagger';
import { ApiSuccessResponse } from '../common/dto/api-response.dto';

@ApiTags('Likes')
@ApiBearerAuth()
@Controller('likes')
@UseGuards(AccessTokenGuard)
export class LikeController {
  constructor(private readonly likeService: LikeService) {}

  @Post(':postId')
  async likePost(@Req() req, @Param('postId') postId: number) {
    const userId = req.user['sub'];
    const like = await this.likeService.createLike(userId, postId);
    return ApiSuccessResponse.of(like, 'Like created');
  }

  @Delete(':likeId')
  async unlikePost(@Req() req, @Param('likeId') likeId: number) {
    const userId = req.user['sub'];
    await this.likeService.deleteLike(userId, likeId);
    return ApiSuccessResponse.of(null, 'Like deleted');
  }

  @Get('post/:postId')
  async getLikesForPost(@Param('postId') postId: number) {
    const likes = await this.likeService.getLikesForPost(postId);
    return ApiSuccessResponse.of(likes, 'Likes fetched successfully');
  }
}