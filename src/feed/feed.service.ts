import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { Post } from '../post/entities/post.entity';
import { Follow } from '../follow/entities/follow.entity';
import { plainToClass } from 'class-transformer';
import { PostResponseDto } from '../post/dto/post-response.dto';
import { PaginationDto } from './dto/pagination.dto';

@Injectable()
export class FeedService {
  constructor(
    @InjectRepository(Post) private postRepository: Repository<Post>,
    @InjectRepository(Follow) private followRepository: Repository<Follow>,
  ) {}

  // feed.service.ts
  async getUserFeed(userId: number, pagination: PaginationDto) {
    const { cursor, limit = 10 } = pagination;
    
    const follows = await this.followRepository.find({
      where: { follower: { id: userId } },
      relations: ['following'],
    });
    const followedUserIds = follows.map(follow => follow.following.id);

    const query = this.postRepository.createQueryBuilder('post')
      .leftJoinAndSelect('post.user', 'user')
      .leftJoinAndSelect('post.project', 'project')
      .where('post.user IN (:...userIds)', { userIds: followedUserIds })
      .andWhere('post.deletedAt IS NULL')
      .orderBy('post.id', 'DESC')
      .limit(limit);

    if (cursor) {
      query.andWhere('post.id < :cursor', { cursor });
    }

    const [posts, total] = await query.getManyAndCount();
    const postDtos = posts.map(post => this.mapPostToDto(post));
    
    const nextCursor = posts.length > 0 ? posts[posts.length - 1].id : null;

    return {
      posts: postDtos,
      total,
      nextCursor,
      limit
    };
  }

  async getTrendingPosts(limit = 10): Promise<PostResponseDto[]> {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const posts = await this.postRepository.createQueryBuilder('post')
      .leftJoinAndSelect('post.user', 'user')
      .leftJoinAndSelect('post.project', 'project')
      .leftJoin('post.likes', 'like')
      .where('post.deletedAt IS NULL')
      .andWhere('post.createdAt >= :sevenDaysAgo', { sevenDaysAgo })
      .groupBy('post.id')
      .addGroupBy('user.id')
      .addGroupBy('project.id')
      .orderBy('COUNT(like.id)', 'DESC')
      .limit(limit)
      .getMany();

    return posts.map(post => this.mapPostToDto(post));
  }

  async getRecentPosts(limit = 10): Promise<PostResponseDto[]> {
    const posts = await this.postRepository.createQueryBuilder('post')
      .leftJoinAndSelect('post.user', 'user')
      .leftJoinAndSelect('post.project', 'project')
      .where('post.deletedAt IS NULL')
      .orderBy('post.createdAt', 'DESC')
      .limit(limit)
      .getMany();
    return posts.map(post => this.mapPostToDto(post));
  }

  async getExplorePosts(limit = 10): Promise<PostResponseDto[]> {
    const posts = await this.postRepository.createQueryBuilder('post')
      .leftJoinAndSelect('post.user', 'user')
      .leftJoinAndSelect('post.project', 'project')
      .where('post.deletedAt IS NULL')
      .orderBy('RANDOM()')
      .limit(limit)
      .getMany();
    return posts.map(post => this.mapPostToDto(post));
  }

  private mapPostToDto(post: Post): PostResponseDto {
    return plainToClass(PostResponseDto, post, {
      excludeExtraneousValues: true,
    });
  }
}