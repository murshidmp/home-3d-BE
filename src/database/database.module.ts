import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      useFactory: async (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get<string>('database.host'),
        port: +configService.get<string>('database.port'),
        username: configService.get<string>('database.user'),
        password: configService.get<string>('database.password'),
        database: configService.get<string>('database.name'),
        entities: [__dirname + '/../**/*.entity{.ts,.js}'],
        synchronize: true, // Disable in production for safety
        extra: {
          max: configService.get<number>('database.poolMax') || 10, // Maximum number of connections
          min: configService.get<number>('database.poolMin') || 2, // Minimum number of connections
          idleTimeoutMillis: configService.get<number>('database.poolIdleTimeout') || 30000, // Close idle connections after 30 seconds
          connectionTimeoutMillis: configService.get<number>('database.poolConnectionTimeout') || 2000, // Timeout for a connection attempt
        },
      }),
      inject: [ConfigService],
    }),
    // Add other connections if needed
  ],
})
export class DatabaseModule {}
