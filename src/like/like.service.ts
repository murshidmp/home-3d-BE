import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Like } from './entities/like.entity';
import { Post } from '../post/entities/post.entity';
import { User } from '../user/entities/user.entity';
import { plainToClass } from 'class-transformer';
import { LikeResponseDto } from './dto/like-response.dto';

@Injectable()
export class LikeService {
  constructor(
    @InjectRepository(Like) private readonly likeRepository: Repository<Like>,
    @InjectRepository(Post) private readonly postRepository: Repository<Post>,
    @InjectRepository(User) private readonly userRepository: Repository<User>,
  ) {}

  async createLike(userId: number, postId: number): Promise<LikeResponseDto> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    const post = await this.postRepository.findOne({ where: { id: postId } });
    if (!user || !post) throw new NotFoundException('User or Post not found');
    
    const existingLike = await this.likeRepository.findOne({
      where: { 
        user: { id: userId }, 
        post: { id: postId } 
      },
    });
    if (existingLike) throw new ForbiddenException('You already liked this post');
    
    const like = this.likeRepository.create({ user, post });
    const savedLike = await this.likeRepository.save(like);

    post.likeCount += 1;
    await this.postRepository.save(post);

    return this.mapLikeToDto(savedLike);
  }

  async deleteLike(userId: number, likeId: number): Promise<void> {
    const like = await this.likeRepository.findOne({ where: { id: likeId }, relations: ['user', 'post'] });
    if (!like) throw new NotFoundException('Like not found');
    if (like.user.id !== userId) throw new ForbiddenException('You do not own this like');

    await this.likeRepository.remove(like);

    like.post.likeCount -= 1;
    await this.postRepository.save(like.post);
  }

  async getLikesForPost(postId: number): Promise<LikeResponseDto[]> {
    const likes = await this.likeRepository.find({ where: { post: { id: postId } }, relations: ['user'] });
    return likes.map(like => this.mapLikeToDto(like));
  }

  private mapLikeToDto(like: Like): LikeResponseDto {
    return plainToClass(LikeResponseDto, like, { excludeExtraneousValues: true });
  }
}