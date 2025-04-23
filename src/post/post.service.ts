import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Post } from './entities/post.entity';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { User } from '../user/entities/user.entity';
import { Project } from '../project/entities/project.entity';

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

  async createPost(userId: number, dto: CreatePostDto): Promise<Post> {
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
    return await this.postRepository.save(post);
  }

  async getPostById(postId: number): Promise<Post> {
    const post = await this.postRepository.findOne({ where: { id: postId } });
    if (!post) throw new NotFoundException('Post not found');
    return post;
  }

  async getPostsForUser(userId: number): Promise<Post[]> {
    return this.postRepository.find({
      where: { user: { id: userId } },
      order: { createdAt: 'DESC' },
    });
  }

  async updatePost(postId: number, dto: UpdatePostDto): Promise<Post> {
    const post = await this.getPostById(postId);
    if (dto.imageUrl !== undefined) post.imageUrl = dto.imageUrl;
    if (dto.description !== undefined) post.description = dto.description;
    return await this.postRepository.save(post);
  }

  async deletePost(postId: number): Promise<void> {
    const post = await this.getPostById(postId);
    await this.postRepository.softRemove(post);
  }
}
