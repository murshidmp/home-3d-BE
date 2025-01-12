import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { User } from 'src/users/entities/user.entity';
import { Admin } from 'src/admin/entities/admin.entity';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      name: 'main', //This is the name of the connection
      useFactory: async (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get<string>('databaseMain.host'),
        port: +configService.get<string>('databaseMain.port'),
        username: configService.get<string>('databaseMain.user'),
        password: configService.get<string>('databaseMain.password'),
        database: configService.get<string>('databaseMain.name'),
        entities: [User, Admin],
        synchronize: true, 
      }),
      inject: [ConfigService],
    }),
    //Add if any other connection is needed
  ],
})
export class DatabaseModule {}