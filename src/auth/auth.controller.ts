import {
  Body,
  Controller,
  Get,
  Post,
  Patch,
  Query,
  Req,
  Param,
  UseGuards,
  Res,
  Delete,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AccessTokenGuard } from 'src/common/guards/accessToken.guard';
import { RefreshTokenGuard } from 'src/common/guards/refreshToken.guard';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { CreateAdminDto } from '../admin/dto/create-admin.dto';
import { AdminSignInDto } from './dto/admin-signin.dto';
import { ApiBearerAuth, ApiBody, ApiTags } from '@nestjs/swagger';
import { emailDto } from './dto/email.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ChangeEmailDto } from './dto/change-email-admin.dto';
import { AccountDeletedGuard } from 'src/common/guards/accountDeleted.guard';
import { UsersService } from 'src/user/users.service';
import { CreateUserDto } from 'src/user/dto/create-user.dto';


@ApiBearerAuth()
@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService,private readonly usersService: UsersService) { }
    
  /** 
    Admin Auth 🛡️
  */
  @Get('admin/email-check')
  async checkAdminEmail(@Query() emaildto: emailDto) {
    return await this.authService.checkAdminEmail(emaildto.email);
  }


  @UseGuards(RefreshTokenGuard)
  @Get('admin/refresh-token')
  adminRefreshTokens(@Req() req: any) {
    const userId = req.user['sub'];
    const refreshToken = req.user['refreshToken'];
    return this.authService.adminRefreshTokens(userId, refreshToken);
  }

  @Post('admin/signup')
  adminSignup(@Body() CreateAdminDto: CreateAdminDto) {
    
    
    return this.authService.adminSignUp(CreateAdminDto);
  }

  @Post('admin/signin')
  adminSignin(@Body() AdminSignInDto: AdminSignInDto) {
    return this.authService.adminSignIn(AdminSignInDto);
  }

 
  @UseGuards(AccessTokenGuard)
  @Get('admin/logout')
  adminlogout(@Req() req: any) {
    console.log(req);
    
    return this.authService.adminLogout(req.user['sub']);
  }

  // @UseGuards(AccessTokenGuard)
  // @Post('passwordchangeadmin/:email')
  // async changePassword(
  //   @Param('email') email: string,
  //   @Body() changePasswordDto: ChangePasswordDto,
  // ) {
  //   try {
  //     const result = await this.authService.adminPasswordChange(email, changePasswordDto);
  //     return result;
  //   } catch (error) {
  //     throw error;
  //   }
  // }

  @Post('admin/forgot-password')
  async forForgotPasswordAdmin(
    @Req() req: Request,
    @Body() emailDto: emailDto,
  ) {
    return this.authService.sendEmailforResetPassword(
      req.headers.host,
      emailDto.email,
    );
  }

  @Post('admin/reset-password/:token')
  async resetPasswordAdmin(
    @Param('token') token: string,
    @Body() body: ResetPasswordDto,
  ) {
    return this.authService.resetPasswordAdmin(token, body.password);
    
  }


  @Post('admin/set-password/:token')
  async setPasswordAdmin(
    @Param('token') token: string,
    @Body() body: ResetPasswordDto,
  ) {
    return this.authService.setPasswordAdmin(token, body.password);
    
  }

  @UseGuards(AccessTokenGuard)
  @Delete('admin/delete-all-data')
  async deleteAllData() {
    // return this.usersService.deleteAllRecords();
  }
  
  // @Get('resident')
  // getResident(@Req() req: Request) {
  // const data =this.authService.getResident();
  
  // return  data 
  //   }

    
  /** 
    User Auth 🛡️
  */

  @Get('user/email-check')
  async checkUserEmail(@Query() emaildto: emailDto) {
    return await this.authService.checkUserEmail(emaildto.email);
  }
  @Post('user/signup')
  signup(@Body() createUserDto: CreateUserDto) {
    return this.authService.userSignUp(createUserDto);
  }

  @Post('user/signin')
  signin(@Body() data: AuthDto) {
    
    return this.authService.userSignIn(data);
  }


  @Get('user/validate-email')
  async checkEmail(@Query() queryString: emailDto) {
    return await this.authService.userCheckEmail(queryString.email);
  }


  @UseGuards(AccessTokenGuard)
  @Get('user/logout')
  logout(@Req() req: any) {
    return this.authService.userLogout(req.user['sub']);
  }

  @UseGuards(RefreshTokenGuard)
  @Get('user/refresh-token')
  refreshTokens(@Req() req: any) {
    const userId = req.user['sub'];
    const refreshToken = req.user['refreshToken'];
    return this.authService.userRefreshTokens(userId, refreshToken);
  }

  @Post('user/forgot-password')
  async forgotPasswordUser(@Body() email: emailDto) {
    return this.authService.forgotPasswordUser(email.email);
  }
 
  @Post('user/reset-password/:token')
  async resetPassword(
    @Param('token') token: string,
    @Body() body: ResetPasswordDto,
  ) {
    return this.authService.resetPasswordUser(token, body.password);
  }
   
  // @UseGuards(AccessTokenGuard)
  // @Get('user/init')
  // async init(@Req() req: any) {
  //   return this.authService.init(+req.user['sub']);
  // }

  @Delete('user/account-delete-web')
  deleteMyAccount(@Body() data: AuthDto) {
    return this.authService.accountDeleteWeb(data);
  }  
  
}
