import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { CustomConfigModule } from './config/config.module';
import { DatabaseModule } from './database/database.module';
import { LoggerModule } from './logger/logger.module';
import { UsersModule } from './user/users.module';
import { AuthModule } from './auth/auth.module';
import { ProjectModule } from './project/project.module';
import { BookmarkModule } from './bookmark/bookmark.module';
import { RenderingModule } from './rendering/rendering.module';
import { FollowModule } from './follow/follow.module';
import { FeedModule } from './feed/feed.module';
import { PostModule } from './post/post.module';
import { LikeModule } from './like/like.module';
import { CommentModule } from './comment/comment.module';



@Module({
  imports: [
    CustomConfigModule,
    DatabaseModule,
    LoggerModule,
    AuthModule,
    UsersModule,
    ProjectModule,
    PostModule,
    FeedModule,
    FollowModule,
    RenderingModule,
    BookmarkModule,
    LikeModule,
    CommentModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
