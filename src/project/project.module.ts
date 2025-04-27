// src/project/project.module.ts
import { Module } from '@nestjs/common';
import { ProjectService } from './project.service';
import { ProjectController } from './project.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Project } from './entities/project.entity';
import { User } from '../user/entities/user.entity';
import { ProjectVersion } from './entities/project-version.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Project, User, ProjectVersion])],
  controllers: [ProjectController],
  providers: [ProjectService],
  exports: [ProjectService],
})
export class ProjectModule {}
