import {
    Controller,
    Post as HttpPost,
    Get,
    Patch,
    Delete,
    Body,
    Param,
    Req,
    HttpCode,
    HttpStatus,
    UseGuards,
  } from '@nestjs/common';
  import { ApiTags, ApiBearerAuth, ApiResponse } from '@nestjs/swagger';
  import { PostService } from './post.service';
  import { CreatePostDto } from './dto/create-post.dto';
  import { UpdatePostDto } from './dto/update-post.dto';
  import { AccessTokenGuard } from '../common/guards/accessToken.guard';
  import { ApiSuccessResponse } from '../common/dto/api-response.dto';
  
  @ApiTags('Posts')
  @ApiBearerAuth()
  @UseGuards(AccessTokenGuard)
  @Controller('posts')
  export class PostController {
    constructor(private readonly postService: PostService) {}
  
    @HttpPost()
    @HttpCode(HttpStatus.CREATED)
    @ApiResponse({ status: 201, description: 'Post created successfully.' })
    async create(@Req() req: any, @Body() dto: CreatePostDto) {
      const userId = req.user.sub;
      const post = await this.postService.createPost(userId, dto);
      return ApiSuccessResponse.of(post, 'Post created successfully');
    }
  
    @Get(':id')
    @HttpCode(HttpStatus.OK)
    @ApiResponse({ status: 200, description: 'Post fetched successfully.' })
    async getPost(@Param('id') id: number) {
      const post = await this.postService.getPostById(id);
      return ApiSuccessResponse.of(post, 'Post fetched successfully');
    }
  
    @Get()
    @HttpCode(HttpStatus.OK)
    @ApiResponse({ status: 200, description: 'List of user posts fetched successfully.' })
    async getPosts(@Req() req: any) {
      const userId = req.user.sub;
      const posts = await this.postService.getPostsForUser(userId);
      return ApiSuccessResponse.of(posts, 'Posts fetched successfully');
    }
  
    @Patch(':id')
    @HttpCode(HttpStatus.OK)
    @ApiResponse({ status: 200, description: 'Post updated successfully.' })
    async update(@Param('id') id: number, @Body() dto: UpdatePostDto) {
      const post = await this.postService.updatePost(id, dto);
      return ApiSuccessResponse.of(post, 'Post updated successfully');
    }
  
    @Delete(':id')
    @HttpCode(HttpStatus.OK)
    @ApiResponse({ status: 200, description: 'Post deleted successfully.' })
    async delete(@Param('id') id: number) {
      await this.postService.deletePost(id);
      return ApiSuccessResponse.of(null, 'Post deleted successfully');
    }
  }
  