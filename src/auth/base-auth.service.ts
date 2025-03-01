// base-auth.service.ts
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class BaseAuthService {
  constructor(
    protected readonly jwtService: JwtService,
    protected readonly configService: ConfigService,
  ) {}

  /**
   * Generates both an access token and a refresh token.
   * 
   * @param userId - The user's ID
   * @param email - The user's email
   * @returns an object containing `accessToken` and `refreshToken`
   */
  protected async generateTokens(userId: number, email: string) {
    const payload = { sub: userId, email };

    // JWT secrets & expirations typically come from your .env or config
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('jwtSecretKeys.access') || 'ACCESS_SECRET',
      expiresIn: this.configService.get<string>('jwtSecretKeys.accessExp') || '16m',
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('jwtSecretKeys.refresh') || 'REFRESH_SECRET',
      expiresIn: this.configService.get<string>('jwtSecretKeys.refreshExp') || '7d',
    });

    return {
      accessToken,
      refreshToken,
    };
  }
}
