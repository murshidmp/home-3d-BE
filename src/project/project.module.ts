import { Module } from '@nestjs/common';
import { ProjectController } from './project.controller';
import { ProjectService } from './project.service';
import { ProjectService } from './project.service';
import { ProjectController } from './project.controller';

@Module({
  controllers: [ProjectController],
  providers: [ProjectService]
})
export class ProjectModule {}
