import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      useFactory: async (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get<string>('databaseMain.host'),
        port: +configService.get<string>('databaseMain.port'),
        username: configService.get<string>('databaseMain.user'),
        password: configService.get<string>('databaseMain.password'),
        database: configService.get<string>('databaseMain.name'),
        entities: [__dirname + '/../**/*.entity{.ts,.js}'],
        synchronize: true, // Disable in production for safety
        extra: {
          max: configService.get<number>('databaseMain.poolMax') || 10, // Maximum number of connections
          min: configService.get<number>('databaseMain.poolMin') || 2, // Minimum number of connections
          idleTimeoutMillis: configService.get<number>('databaseMain.poolIdleTimeout') || 30000, // Close idle connections after 30 seconds
          connectionTimeoutMillis: configService.get<number>('databaseMain.poolConnectionTimeout') || 2000, // Timeout for a connection attempt
        },
      }),
      inject: [ConfigService],
    }),
    // Add other connections if needed
  ],
})
export class DatabaseModule {}
