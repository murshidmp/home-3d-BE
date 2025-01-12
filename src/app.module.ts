import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { CustomConfigModule } from './config/config.module';
import { DatabaseModule } from './database/database.module';
import { LoggerModule } from './logger/logger.module';
import { UsersModule } from './users/users.module';
import { AdminModule } from './admin/admin.module';
import { AuthModule } from './auth/auth.module';
import { ProjectModule } from './project/project.module';
import { BookmarkModule } from './bookmark/bookmark.module';
import { RenderingModule } from './rendering/rendering.module';
import { FollowModule } from './follow/follow.module';
import { FeedModule } from './feed/feed.module';
import { PostModule } from './post/post.module';



@Module({
  imports: [
    CustomConfigModule,
    DatabaseModule,
    LoggerModule,
    AuthModule,
    AdminModule,
    UsersModule,
    ProjectModule,
    PostModule,
    FeedModule,
    FollowModule,
    RenderingModule,
    BookmarkModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
