import {
  Controller,
  Post as PostMethod,
  Body,
  Get,
  Param,
  Patch,
  Delete,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { PostService } from './post.service';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { ApiTags, ApiBearerAuth, ApiResponse } from '@nestjs/swagger';
import { ApiSuccessResponse } from '../common/dto/api-response.dto';

@ApiTags('Posts')
@ApiBearerAuth()
@UseGuards(AccessTokenGuard)
@Controller('posts')
export class PostController {
  constructor(private readonly postService: PostService) {}

  @PostMethod()
  @HttpCode(HttpStatus.CREATED)
  @ApiResponse({ status: 201, description: 'Post created successfully.' })
  async create(@Req() req: any, @Body() dto: CreatePostDto) {
    const userId = req.user['sub'];
    const post = await this.postService.createPost(userId, dto);
    return ApiSuccessResponse.of(post, 'Post created');
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'List of user posts.' })
  async findAll(@Req() req: any) {
    const userId = req.user['sub'];
    const posts = await this.postService.getPostsForUser(userId);
    return ApiSuccessResponse.of(posts, 'Posts fetched successfully');
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'Post fetched successfully.' })
  async findOne(@Req() req: any, @Param('id') id: number) {
    const post = await this.postService.getPostById(id);
    return ApiSuccessResponse.of(post, 'Post fetched');
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'Post updated successfully.' })
  async update(
    @Req() req: any,
    @Param('id') id: number,
    @Body() dto: UpdatePostDto,
  ) {
    const userId = req.user['sub'];
    const post = await this.postService.updatePost(userId, id, dto);
    return ApiSuccessResponse.of(post, 'Post updated');
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'Post deleted (soft) successfully.' })
  async remove(@Req() req: any, @Param('id') id: number) {
    const userId = req.user['sub'];
    await this.postService.deletePost(userId, id);
    return ApiSuccessResponse.of(null, 'Post deleted');
  }
}