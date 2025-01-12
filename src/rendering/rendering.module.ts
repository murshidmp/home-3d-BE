import { Module } from '@nestjs/common';
import { RenderingController } from './rendering.controller';
import { RenderingService } from './rendering.service';

@Module({
  controllers: [RenderingController],
  providers: [RenderingService]
})
export class RenderingModule {}
