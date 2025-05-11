import { Controller, Get, Query, UseGuards, Req } from '@nestjs/common';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { FeedService } from './feed.service';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { PaginationDto } from './dto/pagination.dto';

@ApiTags('Feed')
@ApiBearerAuth()
@Controller('feed')
@UseGuards(AccessTokenGuard)
export class FeedController {
  constructor(private readonly feedService: FeedService) {}

// feed.controller.ts
  @Get()
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
}