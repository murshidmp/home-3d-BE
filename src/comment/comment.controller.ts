import { Controller, Post, Delete, Get, Param, Body, UseGuards, Req, HttpCode, HttpStatus } from '@nestjs/common';
import { CommentService } from './comment.service';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { ApiSuccessResponse } from '../common/dto/api-response.dto';
import { CreateCommentDto } from './dto/create-comment.dto';

@ApiTags('Comments')
@ApiBearerAuth()
@Controller('comments')
@UseGuards(AccessTokenGuard)
export class CommentController {
  constructor(private readonly commentService: CommentService) {}

  @Post(':postId')
  @HttpCode(HttpStatus.CREATED)
  async addComment(@Req() req, @Param('postId') postId: number, @Body() dto: CreateCommentDto) {
    const userId = req.user['sub'];
    const comment = await this.commentService.createComment(userId, postId, dto.content);
    return ApiSuccessResponse.of(comment, 'Comment created');
  }

  @Delete(':commentId')
  @HttpCode(HttpStatus.OK)
  async deleteComment(@Req() req, @Param('commentId') commentId: number) {
    const userId = req.user['sub'];
    await this.commentService.deleteComment(userId, commentId);
    return ApiSuccessResponse.of(null, 'Comment deleted');
  }

  @Get('post/:postId')
  @HttpCode(HttpStatus.OK)
  async getCommentsForPost(@Param('postId') postId: number) {
    const comments = await this.commentService.getCommentsForPost(postId);
    return ApiSuccessResponse.of(comments, 'Comments fetched');
  }
}