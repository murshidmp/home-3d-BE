import {
    Controller,
    Post,
    Delete,
    Get,
    Param,
    UseGuards,
    Req,
    HttpCode,
    HttpStatus,
  } from '@nestjs/common';
  import { AccessTokenGuard } from '../common/guards/accessToken.guard';
  import { BookmarkService } from './bookmark.service';
  import { ApiTags, ApiBearerAuth, ApiResponse } from '@nestjs/swagger';
  import { ApiSuccessResponse } from '../common/dto/api-response.dto';
  
  @ApiTags('Bookmarks')
  @ApiBearerAuth()
  @Controller('bookmarks')
  @UseGuards(AccessTokenGuard)
  export class BookmarkController {
    constructor(private readonly bookmarkService: BookmarkService) {}
  
    @Post(':postId')
    @HttpCode(HttpStatus.CREATED)
    @ApiResponse({ status: 201, description: 'Post bookmarked successfully.' })
    async bookmarkPost(@Req() req, @Param('postId') postId: number) {
      const userId = req.user['sub'];
      const bookmark = await this.bookmarkService.bookmarkPost(userId, postId);
      return ApiSuccessResponse.of(bookmark, 'Post bookmarked');
    }
  
    @Delete(':postId')
    @HttpCode(HttpStatus.OK)
    @ApiResponse({ status: 200, description: 'Bookmark removed successfully.' })
    async removeBookmark(@Req() req, @Param('postId') postId: number) {
      const userId = req.user['sub'];
      await this.bookmarkService.removeBookmark(userId, postId);
      return ApiSuccessResponse.of(null, 'Bookmark removed');
    }
  
    @Get()
    @HttpCode(HttpStatus.OK)
    @ApiResponse({ status: 200, description: 'Bookmarks fetched successfully.' })
    async getBookmarks(@Req() req) {
      const userId = req.user['sub'];
      const bookmarks = await this.bookmarkService.getBookmarksForUser(userId);
      return ApiSuccessResponse.of(bookmarks, 'Bookmarks fetched');
    }
  }