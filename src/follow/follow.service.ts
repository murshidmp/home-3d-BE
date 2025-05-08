import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Follow } from './entities/follow.entity';
import { User } from '../user/entities/user.entity';
import { plainToClass } from 'class-transformer';
import { FollowResponseDto } from './dto/follow-response.dto';

@Injectable()
export class FollowService {
  constructor(
    @InjectRepository(Follow)
    private readonly followRepository: Repository<Follow>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async followUser(followerId: number, followingId: number): Promise<FollowResponseDto> {
    if (followerId === followingId) {
      throw new ForbiddenException('You cannot follow yourself');
    }

    const follower = await this.userRepository.findOne({ where: { id: followerId } });
    const following = await this.userRepository.findOne({ where: { id: followingId } });
    if (!follower || !following) {
      throw new NotFoundException('User not found');
    }

    const existingFollow = await this.followRepository.findOne({
      where: { follower: { id: followerId }, following: { id: followingId } },
    });
    if (existingFollow) {
      throw new ForbiddenException('You are already following this user');
    }

    const follow = this.followRepository.create({ follower, following });
    const savedFollow = await this.followRepository.save(follow);
    return this.mapFollowToDto(savedFollow);
  }

  async unfollowUser(followerId: number, followingId: number): Promise<void> {
    const follow = await this.followRepository.findOne({
      where: { follower: { id: followerId }, following: { id: followingId } },
    });
    if (!follow) {
      throw new NotFoundException('Follow relationship not found');
    }
    await this.followRepository.remove(follow);
  }

  async getFollowers(userId: number): Promise<FollowResponseDto[]> {
    const follows = await this.followRepository.find({
      where: { following: { id: userId } },
      relations: ['follower'],
    });
    return follows.map(follow => this.mapFollowToDto(follow));
  }

  async getFollowing(userId: number): Promise<FollowResponseDto[]> {
    const follows = await this.followRepository.find({
      where: { follower: { id: userId } },
      relations: ['following'],
    });
    return follows.map(follow => this.mapFollowToDto(follow));
  }

  private mapFollowToDto(follow: Follow): FollowResponseDto {
    return plainToClass(FollowResponseDto, follow, {
      excludeExtraneousValues: true,
    });
  }
}