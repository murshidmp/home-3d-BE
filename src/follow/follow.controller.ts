import { Controller, Post, Delete, Get, Param, UseGuards, Req, HttpCode, HttpStatus } from '@nestjs/common';
import { FollowService } from './follow.service';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { ApiTags, ApiBearerAuth, ApiResponse } from '@nestjs/swagger';
import { ApiSuccessResponse } from '../common/dto/api-response.dto';

@ApiTags('Follows')
@ApiBearerAuth()
@Controller('follows')
@UseGuards(AccessTokenGuard)
export class FollowController {
  constructor(private readonly followService: FollowService) {}

  @Post(':followingId')
  @HttpCode(HttpStatus.CREATED)
  @ApiResponse({ status: 201, description: 'Successfully followed the user.' })
  @ApiResponse({ status: 403, description: 'Cannot follow yourself or already following.' })
  async followUser(@Req() req, @Param('followingId') followingId: number) {
    const followerId = req.user['sub'];
    const follow = await this.followService.followUser(followerId, followingId);
    return ApiSuccessResponse.of(follow, 'Successfully followed the user');
  }

  @Delete(':followingId')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'Successfully unfollowed the user.' })
  @ApiResponse({ status: 404, description: 'Follow relationship not found.' })
  async unfollowUser(@Req() req, @Param('followingId') followingId: number) {
    const followerId = req.user['sub'];
    await this.followService.unfollowUser(followerId, followingId);
    return ApiSuccessResponse.of(null, 'Successfully unfollowed the user');
  }

  @Get('followers/:userId')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'Successfully fetched followers.' })
  async getFollowers(@Param('userId') userId: number) {
    const followers = await this.followService.getFollowers(userId);
    return ApiSuccessResponse.of(followers, 'Followers fetched successfully');
  }

  @Get('following/:userId')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'Successfully fetched following list.' })
  async getFollowing(@Param('userId') userId: number) {
    const following = await this.followService.getFollowing(userId);
    return ApiSuccessResponse.of(following, 'Following list fetched successfully');
  }
}