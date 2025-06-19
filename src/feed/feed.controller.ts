import { Controller, Get, Query, UseGuards, Req } from '@nestjs/common';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { FeedService } from './feed.service';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { PaginationDto } from './dto/pagination.dto';

@ApiTags('Feed')
@Controller('feed')
export class FeedController {
  constructor(private readonly feedService: FeedService) {}

  @ApiBearerAuth()
  @Get()
  @UseGuards(AccessTokenGuard)
  async getUserFeed(@Req() req, @Query() paginationDto: PaginationDto) {
    const userId = req.user['sub'];
    const result = await this.feedService.getUserFeed(userId, paginationDto);
    
    return {
      data: result.posts,
      nextCursor: result.nextCursor,
      limit: result.limit,
      hasMore: result.posts.length === result.limit,
    };
  }

  @Get('trending')
  async getTrendingPosts(@Query('limit') limit: number = 10) {
    const posts = await this.feedService.getTrendingPosts(limit);
    return { data: posts, limit };
  }

  @Get('recent')
  async getRecentPosts(@Query('limit') limit: number = 10) {
    const posts = await this.feedService.getRecentPosts(limit);
    return { data: posts, limit };
  }

  @Get('explore')
  async getExplorePosts(@Query('limit') limit: number = 10) {
    const posts = await this.feedService.getExplorePosts(limit);
    return { data: posts, limit };
  }
}