import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';

import { UsersService } from '../user/users.service';
import { BaseAuthService } from './base-auth.service';
import { AuthDto } from './dto/login.dto';
import { CreateUserDto } from '../user/dto/create-user.dto';

@Injectable()
export class AuthService extends BaseAuthService {
  constructor(
    protected readonly jwtService: JwtService,
    protected readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    super(jwtService, configService);
  }

  /**
   * Signs up a new user (email + password).
   */
  async userSignUp(createUserDto: CreateUserDto) {
    const existingUser = await this.usersService.findByEmail(createUserDto.email);
    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    const hashedPassword = await argon2.hash(createUserDto.password);
    const user = await this.usersService.create({
      ...createUserDto,
      password: hashedPassword, // Ensure your entity expects `password` or `passwordHash`
    });

    // Generate tokens
    const tokens = await this.generateTokens(user.id, user.email);
    // Store hashed refresh token in DB
    await this.usersService.updateRefreshToken(user.id, tokens.refreshToken);

    // Return tokens + basic user info
    return {
      userId: user.id,
      email: user.email,
      username:user.username,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: this.configService.get<number>('jwtSecretKeys.accessExp'), // e.g. 900 seconds
    };
  }

  /**
   * Signs in an existing user (checks credentials).
   */
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

  /**
   * Logs out a user by clearing the refresh token in DB (so it can’t be reused).
   */
  async userLogout(userId: number) {
    // Clear the user's refresh token from the DB
    await this.usersService.clearRefreshToken(userId);
    return { message: 'User logged out successfully' };
  }

  /**
   * Refreshes access/refresh tokens if the provided refresh token is valid.
   */
  async userRefreshTokens(userId: number, refreshToken: string) {
    const user = await this.usersService.findById(userId);
    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Access Denied');
    }

    // Verify the stored refresh token against the incoming token
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

  /**
   * Sends a password-reset email with a unique token (not fully implemented).
   */
  async forgotPasswordUser(email: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Email not found');
    }

    // Generate a reset token or code here. For example:
    // const resetToken = randomUUID(); // or a JWT
    // Save or hash it in DB, then email it to the user
    // e.g. await this.usersService.saveResetToken(user.id, resetToken);
    // e.g. await this.emailService.sendPasswordResetEmail(user.email, resetToken);

    return { message: 'Password reset email sent (mocked)' };
  }

  /**
   * Resets the user's password given a valid token (not fully implemented).
   */
  async resetPasswordUser(token: string, password: string) {
    // For example:
    // 1. Validate the token from DB or decode if it's a JWT
    // 2. If valid, update the user’s password
    // 3. Clear the reset token so it can’t be reused
    // This is just a placeholder:
    return { message: `Password successfully reset (token=${token}, newPwd=${password})` };
  }

  /**
   * Deletes the user account. Basic example.
   */
  async accountDelete(authDto: AuthDto) {
    // Re-validate user’s credentials or confirm the user’s identity
    const user = await this.validateUser(authDto.email, authDto.password);
    await this.usersService.deleteUser(user.id);

    return { message: 'Account successfully deleted' };
  }

  /**
   * Validates a user by email and password using argon2.
   * Throws UnauthorizedException if invalid.
   */
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
}
