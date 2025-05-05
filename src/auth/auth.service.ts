import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import { OAuth2Client } from 'google-auth-library';
import { UsersService } from '../user/users.service';
import { BaseAuthService } from './base-auth.service';
import { AuthDto } from './dto/login.dto';
import { CreateUserDto } from '../user/dto/create-user.dto';

@Injectable()
export class AuthService extends BaseAuthService {
  private googleClient: OAuth2Client;

  constructor(
    protected readonly jwtService: JwtService,
    protected readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    super(jwtService, configService);
    this.googleClient = new OAuth2Client();
  }

  async userSignUp(createUserDto: CreateUserDto) {
    const existingUser = await this.usersService.findByEmail(createUserDto.email);
    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    const hashedPassword = await argon2.hash(createUserDto.password);
    const user = await this.usersService.create({
      ...createUserDto,
      password: hashedPassword,
    });

    const tokens = await this.generateTokens(user.id, user.email);
    await this.usersService.updateRefreshToken(user.id, tokens.refreshToken);

    return {
      userId: user.id,
      email: user.email,
      username: user.username,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: this.configService.get<number>('jwtSecretKeys.accessExp'),
    };
  }

  async userSignIn(authDto: AuthDto) {
    const user = await this.validateUser(authDto.email, authDto.password);
    const tokens = await this.generateTokens(user.id, user.email);
    await this.usersService.updateRefreshToken(user.id, tokens.refreshToken);

    return {
      user: {
        id: user.id,
        email: user.email,
      },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: this.configService.get<number>('jwtSecretKeys.accessExp'),
    };
  }

  async userLogout(userId: number) {
    await this.usersService.clearRefreshToken(userId);
    return { message: 'User logged out successfully' };
  }

  async userRefreshTokens(userId: number, refreshToken: string) {
    const user = await this.usersService.findById(userId);
    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Access Denied');
    }

    const refreshMatches = await argon2.verify(user.refreshToken, refreshToken);
    if (!refreshMatches) {
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.generateTokens(user.id, user.email);
    await this.usersService.updateRefreshToken(user.id, tokens.refreshToken);

    return {
      user: {
        id: user.id,
        email: user.email,
      },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: this.configService.get<number>('JWT_ACCESS_EXPIRATION'),
    };
  }

  async forgotPasswordUser(email: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Email not found');
    }
    return { message: 'Password reset email sent (mocked)' };
  }

  async resetPasswordUser(token: string, password: string) {
    return { message: `Password successfully reset (token=${token}, newPwd=${password})` };
  }

  async accountDelete(authDto: AuthDto) {
    const user = await this.validateUser(authDto.email, authDto.password);
    await this.usersService.deleteUser(user.id);
    return { message: 'Account successfully deleted' };
  }

  private async validateUser(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const passwordMatches = await argon2.verify(user.password, password);
    if (!passwordMatches) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }

  async googleLogin(idToken: string) {
    try {
      
      const ticket = await this.googleClient.verifyIdToken({
        idToken,
        audience: [
          this.configService.get<string>('google.clientIdWeb'),
          this.configService.get<string>('google.clientIdAndroid'),
          this.configService.get<string>('google.clientIdIos'),
        ].filter(Boolean),
      });
      const payload = ticket.getPayload();
      const googleId = payload['sub'];
      const email = payload['email'];
      const username = payload['name'];

      let user = await this.usersService.findByGoogleId(googleId);
      if (!user) {
        user = await this.usersService.createGoogleUser(googleId, email, username);
      }

      const tokens = await this.generateTokens(user.id, user.email);
      await this.usersService.updateRefreshToken(user.id, tokens.refreshToken);

      return {
        userId: user.id,
        email: user.email,
        username: user.username,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: this.configService.get<number>('jwtSecretKeys.accessExp'),
      };
    } catch (error) {
      console.error('Google login error:', error);
      throw new UnauthorizedException('Invalid Google ID token');
    }
  }

  async setPassword(userId: number, password: string) {
    const hashedPassword = await argon2.hash(password);
    return await this.usersService.update(userId, { password: hashedPassword });
  }
}