import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { FeedController } from './feed.controller';
import { FeedService } from './feed.service';
import { Post } from '../post/entities/post.entity';
import { Follow } from '../follow/entities/follow.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([Post, Follow]),
  ],
  controllers: [FeedController],
  providers: [FeedService],
})
export class FeedModule {}