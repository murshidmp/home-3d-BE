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

  private mapPostToDto(post: Post): PostResponseDto {
    return plainToClass(PostResponseDto, post, {
      excludeExtraneousValues: true,
    });
  }
}