import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/user/users.module';
import { JwtModule } from '@nestjs/jwt';
import { AccessTokenStrategy } from './strategies/accessToken.strategy';
import { RefreshTokenStrategy } from './strategies/refreshToken.strategy';
import { User } from '../user/entities/user.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EmailService } from 'src/common/services/email.service';
import { Admin } from '../admin/entities/admin.entity';
import { AdminModule } from 'src/admin/admin.module';

@Module({
  imports: [
    JwtModule.register({}),
    UsersModule,
    AdminModule,
    TypeOrmModule.forFeature([User, Admin], 'main'),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    // AccessTokenStrategy,
    // RefreshTokenStrategy,
    EmailService,
    
  ],
})
export class AuthModule { }
