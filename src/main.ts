import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { setupSwagger } from './config/swagger.config';
import { ValidationPipe, VersioningType } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({
    transform: true, // Enable transformation
    whitelist: true, // Strip properties that are not in the DTO
    forbidNonWhitelisted: true, // Prevent non-whitelisted properties
  }));
  setupSwagger(app);
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1'
  });
  await app.listen(8080);
}
bootstrap();
