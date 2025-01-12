import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { INestApplication } from '@nestjs/common';

export function setupSwagger(app: any): void {
  const options = new DocumentBuilder()
    .setTitle('home_decor_api')
    .setDescription('API description')
    .addTag('home_decor')
    .setVersion('1.0')
    .addBearerAuth({
      description: 'Enter your JWT token',
      type: 'http',
      in: 'header',
      scheme: 'bearer',
      bearerFormat: 'JWT',
    })
    .build();

  const document = SwaggerModule.createDocument(app, options);
  document.paths = Object.fromEntries(
    Object.entries(document.paths).map(([path, value]) => [`/v1${path}`, value])
  );
  
  SwaggerModule.setup('v1/api', app, document);
}