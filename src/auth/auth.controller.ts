import {
  Body,
  Controller,
  Get,
  Post,
  Param,
  Delete,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AccessTokenGuard } from 'src/common/guards/accessToken.guard';
import { RefreshTokenGuard } from 'src/common/guards/refreshToken.guard';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/login.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { CreateUserDto } from '../user/dto/create-user.dto';
import { ApiBearerAuth, ApiTags, ApiResponse } from '@nestjs/swagger';
import { EmailDto } from './dto/email.dto';
import { ApiSuccessResponse } from 'src/common/dto/api-response.dto';

@ApiBearerAuth()
@ApiTags('Auth API')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // User Auth 🛡️

  @Post('user/signup')
  @HttpCode(HttpStatus.CREATED)
  @ApiResponse({ status: 201, description: 'User successfully signed up.' })
  @ApiResponse({ status: 400, description: 'Bad Request.' })
  async signup(@Body() createUserDto: CreateUserDto) {
    const result = await this.authService.userSignUp(createUserDto);
    return ApiSuccessResponse.of(result, 'User signed up successfully');
  }

  @Post('user/signin')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'User successfully signed in.' })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  async signin(@Body() data: AuthDto) {
    const result = await this.authService.userSignIn(data);
    return ApiSuccessResponse.of(result, 'User signed in successfully');
  }

  @UseGuards(AccessTokenGuard)
  @Get('user/logout')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'User successfully logged out.' })
  async logout(@Req() req: any) {
    const userId = req.user['sub'];
    const result = await this.authService.userLogout(userId);
    return ApiSuccessResponse.of(result, 'User logged out successfully');
  }

  @UseGuards(RefreshTokenGuard)
  @Get('user/refresh-token')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'Token successfully refreshed.' })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  async refreshTokens(@Req() req: any) {
    const userId = req.user['sub'];
    const refreshToken = req.user['refreshToken'];
    const result = await this.authService.userRefreshTokens(userId, refreshToken);
    return ApiSuccessResponse.of(result, 'Token successfully refreshed');
  }

  @Post('user/forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'Password reset email sent.' })
  @ApiResponse({ status: 404, description: 'Email not found.' })
  async forgotPasswordUser(@Body() email: EmailDto) {
    const result = await this.authService.forgotPasswordUser(email.email);
    return ApiSuccessResponse.of(result, 'Password reset email sent');
  }

  @Post('user/reset-password/:token')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'Password successfully reset.' })
  @ApiResponse({ status: 400, description: 'Invalid token.' })
  async resetPassword(@Param('token') token: string, @Body() body: ResetPasswordDto) {
    const result = await this.authService.resetPasswordUser(token, body.password);
    return ApiSuccessResponse.of(result, 'Password reset successfully');
  }

  @Delete('user/account-delete-web')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'Account successfully deleted.' })
  @ApiResponse({ status: 400, description: 'Bad Request.' })
  async deleteMyAccount(@Body() data: AuthDto) {
    const result = await this.authService.accountDelete(data);
    return ApiSuccessResponse.of(result, 'Account successfully deleted');
  }
}
