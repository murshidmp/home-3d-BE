import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Post } from './entities/post.entity';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { User } from '../user/entities/user.entity';
import { Project } from '../project/entities/project.entity';
import { plainToClass } from 'class-transformer';
import { PostResponseDto } from './dto/post-response.dto';

@Injectable()
export class PostService {
  constructor(
    @InjectRepository(Post)
    private readonly postRepository: Repository<Post>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Project)
    private readonly projectRepository: Repository<Project>,
  ) {}

  async createPost(userId: number, dto: CreatePostDto): Promise<PostResponseDto> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    let project = null;
    if (dto.projectId) {
      project = await this.projectRepository.findOne({ where: { id: dto.projectId } });
      if (!project) throw new NotFoundException('Project not found');
    }

    const post = this.postRepository.create({
      imageUrl: dto.imageUrl,
      description: dto.description,
      user,
      project,
    });
    const savedPost = await this.postRepository.save(post);
    return this.mapPostToDto(savedPost);
  }

  async getPostById(postId: number): Promise<PostResponseDto> {
    const post = await this.postRepository.findOne({ 
      where: { id: postId },
      relations: ['user', 'project'],
    });
    if (!post) throw new NotFoundException('Post not found');
    return this.mapPostToDto(post);
  }

  async getPostsForUser(userId: number): Promise<PostResponseDto[]> {
    const posts = await this.postRepository.find({
      where: { user: { id: userId } },
      order: { createdAt: 'DESC' },
      relations: ['user', 'project'],
    });
    return posts.map(post => this.mapPostToDto(post));
  }

  async updatePost(userId: number, postId: number, dto: UpdatePostDto): Promise<PostResponseDto> {
    const post = await this.getPostById(postId);
    if (post.user.id !== userId) {
      throw new ForbiddenException('You do not own this post');
    }
    if (dto.imageUrl !== undefined) post.imageUrl = dto.imageUrl;
    if (dto.description !== undefined) post.description = dto.description;
    const updatedPost = await this.postRepository.save(post);
    return this.mapPostToDto(updatedPost);
  }

  async deletePost(userId: number, postId: number): Promise<void> {
    const post = await this.getPostById(postId);
    if (post.user.id !== userId) {
      throw new ForbiddenException('You do not own this post');
    }
    await this.postRepository.softRemove(post);
  }

  private mapPostToDto(post: Post): PostResponseDto {
    return plainToClass(PostResponseDto, post, {
      excludeExtraneousValues: true,
    });
  }
}