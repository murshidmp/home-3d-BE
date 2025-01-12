import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  HttpStatus,
  NotFoundException,
  UnauthorizedException
} from '@nestjs/common';
// import * as nodemailer from 'nodemailer';
import * as SendGrid from '@sendgrid/mail';
import { UsersService } from 'src/users/users.service';
// import { AdminsService } from 'src/admin/admins.service';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthDto } from './dto/auth.dto';
import { User } from '../users/entities/user.entity';
import { Admin, AdminStatus } from '../admin/entities/admin.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { DeleteResult, In, Repository, UpdateResult } from 'typeorm';
// import { CreateAdminDto } from '../admin/dto/create-admin.dto';
import { emailDto } from './dto/email.dto';
import { chaingePassword } from './dto/chaingePassword-admin.dto';
import { log } from 'console';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ChangeEmailDto } from './dto/change-email-admin.dto';
import { EmailService } from 'src/common/services/email.service';
import { AdminSignInDto } from './dto/admin-signin.dto';
import { Role } from '../common/enums/roles';
import { CreateAdminDto } from 'src/admin/dto/create-admin.dto';
import { BaseURL, EmailTemplate } from 'src/common/templates/templates';
import { AdminService } from 'src/admin/admin.service';
import { CreateUserDto } from 'src/users/dto/create-user.dto';

// import { ConfigKeys } from 'src/common/enums/config';

// import { getSecrets } from 'src/common/services/keyvault';



@Injectable()
export class AuthService {
  @InjectRepository(User, 'main')
  private readonly userRepository: Repository<User>;
  @InjectRepository(Admin, 'main')
  private readonly adminRepository: Repository<Admin>;

  private resident: any;
  constructor(
    private usersService: UsersService,
    private adminsService: AdminService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private emailService: EmailService,
  ) { }
  async userSignUp(createUserDto: CreateUserDto): Promise<any> {
    try {
      // Check if user exists
      const userExistsWithEmail = await this.usersService.checkUserExistence(
        createUserDto.email,
      );
      if (userExistsWithEmail) {
        throw new BadRequestException('Email is already registered');
      }

      // Hash password
      const hash = await this.hashData(createUserDto.password);
      const newUser = await this.usersService.create({
        ...createUserDto,
        password: hash,
      });

      const tokens = await this.getTokens(
        newUser.id,
        newUser.email,
        Role.User,
      );
      const refreshToken = tokens.refreshToken;
      await this.updateRefreshToken(newUser.id, refreshToken);
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        // user: newUser
      };
    } catch (error) {
      throw error;
    }
  }

  async userSignIn(data: AuthDto) {
    try {
      
      // Check if user exists
      const user = await this.usersService.findByEmail(data.email);
      if (!user) throw new BadRequestException('dialog_wrong_mail_or_pwd');
      if (user.active === false) {
        throw new NotFoundException('User is in suspended state');
      }
      // Check password matches
      const passwordMatches = await argon2.verify(user.password, data.password);
      if (!passwordMatches)
        throw new BadRequestException('dialog_wrong_mail_or_pwd');

      // Generate tokens
      const tokens = await this.getTokens(user.id, user.email, Role.User);
      const refreshToken = tokens.refreshToken;
    
      // Update refresh tokens
      await this.updateRefreshToken(user.id, refreshToken);

      // Record user activity
      // this.usersService.recordUserActivity(user.id, UserActivityType.LOGIN);
     
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        // user
      };
    } catch (error) {
      throw error;
    }
  }


  async checkUserEmail(email: string) {
    try {
      const user = await this.usersService.checkUserExistence(email);
      if (!user) {
        return {
          message: 'Email is available',
          isAvailable: true,
         };
      }
      return {
        message: 'Email is already in use',
        isAvailable: false,
      };
    } catch (error) {
      throw error;
    }
  }




  async checkAdminEmail(email: string) {
    try {
      const user = await this.adminsService.checkAdminExistence(email);
      if (!user) {
        return {
          message: 'Email is available',
          isAvailable: true,
         };
      }
      return {
        message: 'Email is already in use',
        isAvailable: false,
      };
    } catch (error) {
      throw error;
    }
  }


  async forgotPasswordUser(email: string) {
    try {
      // check if the provided email is registered with any user
      const user = await this.userRepository.findOneBy({ email })
      if (!user) {
        throw new BadRequestException({
          status: 'error',
          message: 'Email is not registered'
        })
      }
      const token = await this.jwtService.signAsync(
        {
          userId: user.id,
          action: ActionsJwt.ResetPassword,
          password: user.password,
          role: Role.User,
        },
        {
          //secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
          secret: this.configService.get<string>('jwtSecretKey'),
          expiresIn: '24h',
        },
      );

      const emailTemplateData = {
        // passwordResetLink: this.configService.get('RESET_PASSWORD_URL') + token
        passwordResetLink: this.configService.get('userApHost')+'reset-password?token='+token
      }

      // const emailTemplateId = this.configService.get('EMAIL_RESET_PASSWORD_TEMPLATE_ID')
      const emailTemplateId = EmailTemplate.ResetPasswordUser;
      const subject = 'Reset Password';

      const emailResponse =  await this.emailService.sendEmail(
        user.email,
        emailTemplateId,
        emailTemplateData,
        subject,
     );
      
      // console.log('emailResponse', emailResponse);

      const encriptedToken = await argon2.hash(token);
      user.resetPasswordToken = encriptedToken;
      await this.userRepository.save(user);

      // this.usersService.recordUserActivity(user.id, UserActivityType.RESET_PASSWORD);
      if (emailResponse[0]?.statusCode !== 202) {
        throw new BadRequestException('Email could not be sent');
      }
      
      return {
        status: true,
        message: 'pwd_reset_url_sent', //We have sent you a password reset URL.Please check your inbox.
        token: token,
      };
      
    } catch (error) {
      throw error
    }
  }

  async resetPasswordUser(token: string, newPassword: string) {
    try {
      if(!token) {
        throw new BadRequestException('Please provide a valid token');
      }
      const decoded = this.jwtService.verify(token, {
        // secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
        secret: this.configService.get<string>('jwtSecretKey'),
      });
      if(decoded.action !== ActionsJwt.ResetPassword) {
        throw new BadRequestException('Token is invalid');
      }
      const user = await this.userRepository.findOneBy({ id: decoded.userId });
      if(!user) {
        throw new NotFoundException('User account has been deleted');
      }
      const tokenMatches = await argon2.verify(user.resetPasswordToken, token);
      if(!tokenMatches) {
        throw new BadRequestException('Token is invalid');
      }
      if(user && user.active === false) {
        throw new NotFoundException('User has been suspended');
      }
      const hashedPassword = await this.hashData(newPassword);
      user.password = hashedPassword;
      user.resetPasswordToken = null;
      await this.userRepository.save(user);

      // Record user activity
      // this.usersService.recordUserActivity(user.id, UserActivityType.RESET_PASSWORD);
      
      return {
        status: true,
        message: 'Password Reset successfull',
      };

    } catch (error) {
      if (error && error.name === 'TokenExpiredError')
        throw new BadRequestException('Your Supplied token has expired');
      if (error && error.name === 'JsonWebTokenError')
        throw new BadRequestException('Your Supplied token is invalid');
      throw error;
    }
  }

  // async init(userId: number) {
  //   try {
  //     const user = await this.userRepository.findOneBy({ id: userId });
  //     if (!user) {
  //       throw new NotFoundException('User not found');
  //     }
  //     user.refreshToken = undefined;
  //     user.resetPasswordToken = undefined;
  //     user.password = undefined;
  //     user.deviceToken = undefined;
  //     user.active = undefined;
  //     user.createdAt = undefined;
  //     user.updatedAt = undefined;
  //     user.deletedAt = undefined;

  //     // Record user activity
  //     this.usersService.recordUserActivity(userId, UserActivityType.PROFILE_VIEW);

  //     return {
  //       status: 'success',
  //       user,
  //     };
  //   } catch (error) {
  //     throw error;
  //   }
  // }



  async changePasswordUser(
    userId: number,
    changePasswordDto: ChangePasswordDto,
  ) {
    try {
      const { oldPassword, newPassword } = changePasswordDto;
      // check whether the user is active
      const user = await this.userRepository.findOneBy({
        id: userId,
        active: true,
      });
      // user no more exists or suspended
      if (!user) {
        throw new NotFoundException('User has been suspended');
      }
      if (!(await argon2.verify(user.password, oldPassword))) {
        throw new BadRequestException(
          'Please provide the correct current password',
        );
      }
      const hashedNewPassword = await this.hashData(newPassword);
      Object.assign(user, { password: hashedNewPassword });
      await this.userRepository.save(user);
      return {
        status: 'success',
        message: 'Password successfully changed',
      };
    } catch (error) {
      throw error;
    }
  }

    async userLogout(userId: number) {
      // this.userRepository.update(userId, { isIdle: true, refreshToken: null });
      
      // Record user activity
      // this.usersService.recordUserActivity(userId, UserActivityType.LOGOUT);
    // return this.usersService.logout(userId);
  }

  async adminRefreshTokens(adminId: number, refreshToken: string) {
    // admin refresh token
    try {
      const admin = await this.adminsService.findById(adminId);

      if (!admin || !admin.refreshToken)
        throw new ForbiddenException('Access Denied'); // translation required
      const refreshTokenMatches = await argon2.verify(
        admin.refreshToken,
        refreshToken,
      );
      if (!refreshTokenMatches) throw new ForbiddenException('Access Denied'); //translation requird
      const tokens = await this.getTokens(admin.id, admin.name, Role.Admin);
      await this.updateAdminRefreshToken(admin.id, tokens.refreshToken);
      return tokens;
    } catch (error) {
      throw error;
    }
  }

  // user refresh token

  async userRefreshTokens(userId: number, refreshToken: string) {
    try {
      const user = await this.userRepository.findOne({
        where: { id: userId, active: true },
      });
      if (!user || !user.refreshToken)
        throw new ForbiddenException('Access Denied'); // translation required
      const refreshTokenMatches = await argon2.verify(
        user.refreshToken,
        refreshToken,
      );
      if (!refreshTokenMatches) throw new ForbiddenException('Access Denied'); //translation requird
      const tokens = await this.getTokens(user.id, user.email, Role.User);
      //  await this.updateRefreshToken(user.id, tokens.refreshToken);
      tokens.refreshToken = refreshToken;
      return tokens;
    } catch (error) {
      throw error;
    }
  }

  async updateAdminRefreshToken(userId: number, refreshToken: string) {
    try {
      const admin = await this.adminRepository.findOne({
        where: { id: userId, status: In([AdminStatus.Active, AdminStatus.Invited]) },
      });
      if (!admin) throw new ForbiddenException('Access Denied'); // translation required
      const hashedRefreshToken = await this.hashData(refreshToken);
      await this.adminsService.update(userId, {
        refreshToken: hashedRefreshToken,
      });
    } catch (error) {
      throw error;
    }
  }

  hashData(data: string) {
    return argon2.hash(data);
  }

  async updateRefreshToken(userId: number, refreshToken: string) {
    try {
      const hashedRefreshToken = await this.hashData(refreshToken);
      await this.userRepository.update(userId, {
        refreshToken: hashedRefreshToken
        });
    } catch (error) {
      throw error;
    }
  }

  async getTokens(userId: number, username: string, role: string) {
    try {
      const [accessToken, refreshToken] = await Promise.all([
        this.jwtService.signAsync(
          {
            sub: userId,
            username,
            role,
          },
          {
            // secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
            secret: this.configService.get<string>('jwtSecretKeys.access'),
            expiresIn: '24h',
          },
        ),
        this.jwtService.signAsync(
          {
            sub: userId,
            username,
            role,
          },
          {
            // secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
            secret: this.configService.get<string>('jwtSecretKeys.refresh'),
            expiresIn: '365d',
          },
        ),
      ]);

     

      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      throw error;
    }
  }

  /** 
    Admin 🛡️
  */
    async adminSignIn(data: AdminSignInDto) {
    
      try {

    // Check if Admin exists
    const user = await this.adminsService.findByEmail(data.email);
    if (!user) 
    throw new BadRequestException({
      status: HttpStatus.BAD_REQUEST,
      messages: {
        email: 'dialog_wrong_mail_or_pwd',
      },
    }); // Email address does not exist.
    // Check if Admin is deleted
    if (user.deleted === true)
      throw new BadRequestException({
        status: HttpStatus.BAD_REQUEST,
        messages: {
          user: 'dialog_wrong_mail_or_pwd',
        },
      }); //This account has been deleted.


    if (user.status === AdminStatus.Inactive)
      throw new BadRequestException('dialog_accnt_suspended'); //This account has been suspended.


    const passwordMatches = await argon2.verify(user.password, data.password);
    if (!passwordMatches)
      throw new BadRequestException({
        status: HttpStatus.BAD_REQUEST,
        messages: {
          password: 'dialog_wrong_mail_or_pwd',
        },
      });
    const tokens = await this.getTokens(user.id, user.email, user.admin_type);
    await this.updateAdminRefreshToken(user.id, tokens.refreshToken);
    delete user.password;
    delete user.refreshToken;
    delete user.resetPasswordToken;
    return { tokens, user };
  } catch (error) {
    throw error;
  }
}

  async adminSignUp(CreateAdminDto: CreateAdminDto): Promise<any> {
    try {
      // Check if user exists
      const userExists = await this.adminsService.findByEmail(
        CreateAdminDto.email,
      );
      if (userExists) {
        throw new BadRequestException('User already exists');
      }

      // Hash password
      const hash = await this.hashData(CreateAdminDto.password);
      const newUser = await this.adminsService.create({
        ...CreateAdminDto,

        password: hash,
      });
      console.log(newUser);
      
      const tokens = await this.getTokens(
        newUser.id,
        newUser.email,
        newUser.admin_type,
      );
      await this.updateRefreshToken(newUser.id, tokens.refreshToken);
      return tokens;
    } catch (error) {
      throw error;
    }
  }

  async adminLogout(adminId: number) {
    this.adminsService.update(adminId, { refreshToken: null });
    return {
      status: 'success',
      message: 'Logout  successfull',
    };
  }

  async adminPasswordChange(
    email: string,
    changePasswordDto: ChangePasswordDto,
  ) {
    try {
      const { oldPassword, newPassword } = changePasswordDto;
      // check whether the user is active
      const admin = await this.adminRepository.findOneBy({
        email: email,
      });
      // Admin may have removed , inactive(suspended) after logged in
      if (!admin) {
        throw new NotFoundException('User does not exists'); //translation required
      }

      // Admins current password(oldPassword) is incorrect
      if (!(await argon2.verify(admin.password, oldPassword))) {
        throw new BadRequestException({
          status: 'error',
          messages: {
            oldPassword: 'dialog_current_pwd_incorrect', //'Your current password is incorrect.',
          },
        });
      }
      const hashedNewPassword = await this.hashData(newPassword);
      Object.assign(admin, { password: hashedNewPassword });
      
      await this.adminRepository.save(admin);
      return {
        status: 'success',
        message: 'password_changed', //password changed
      };
    } catch (error) {
      throw error;
    }
  }

  async sendEmailforResetPassword(
    hostname: string,
    email: string,
  ): Promise<any> {
    try {
      // const host = this.configService.get<string>('adminHost');
      // const host = ConfigKeys.ADMIN_HOST;
      const user = await this.adminsService.findByEmail(email);
      //Check if the provided email is registered with any user
      if (!user) {
        throw new BadRequestException({
          status: 'error',
          messages: {
            email: 'msg_enter_curr_email',
          },
        }); // Email address does not exist.
      }

if(user.status === AdminStatus.Invited){
  throw new BadRequestException({
    status: 'error',
    messages: {
      email: 'msg_enter_curr_email',
    },
  });

}
      const token = await this.jwtService.signAsync(
        {
          userId: user.id,
          action: ActionsJwt.ResetPassword,
          password: user.password,
          role: user.admin_type,
          status: user.status,
        },
        {
          //secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
          secret: this.configService.get<string>('jwtSecretKey'),
          expiresIn: '24h',
        },
      );

      // baseURL

      // const path = host + BaseURL.ResetPassword + token;
     
      
      const dynamicTemplateData = {
        passwordResetLink: this.configService.get('adminHost')+'auth/reset-password?token='+token,
      };

      const subject = 'Reset Password';

     await this.emailService.sendEmail(
        user.email,
        EmailTemplate.ResetPassword,
       dynamicTemplateData,
        subject,
      );
     return {
        status: 'success',
        message: 'pwd_reset_url_sent', //We have sent you a password reset URL.Please check your inbox.
        // token: token,
      };
    } catch (error) {
      throw error;
    }
  }

  async resetPasswordAdmin(token: string, newPassword: string) {
    try {
      console.log('token', token, newPassword);
      if (!token) {
        throw new BadRequestException('Please provide a valid token'); // translation required
      }
      const decoded = this.jwtService.verify(token, {
        // secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
        secret: this.configService.get<string>('jwtSecretKey'),
      });
      
      

      if (decoded.action !== ActionsJwt.ResetPassword) {
        throw new BadRequestException('token_is_invalid'); // translation required
      }

      const user = await this.adminRepository.findOneBy({ id: decoded.userId });

      if (decoded.password !== user.password) {
        throw new BadRequestException('token_expired');
      }
      if (decoded.status !== AdminStatus.Active) {
        // throw new BadRequestException('token_is_invalid');
        throw new BadRequestException('お使いのアカウントは現在一時停止中です。パスワードの再設定には、担当の管理者までお知らせください。');
      }

      const hashedPassword = await this.hashData(newPassword);

      if (decoded.role === Role.Admin) {
        user.status = AdminStatus.Active;
      }

      Object.assign(user, { password: hashedPassword });
      await this.adminRepository.save(user);
      return {
        status: 'success',
        message: 'password_changed',
        token
      };
    } catch (error) {
      if (error && error.name === 'TokenExpiredError')
        throw new BadRequestException('token_expired');
      if (error && error.name === 'JsonWebTokenError')
        throw new BadRequestException('パスワード再設定に失敗しました。もう一度お試しください。');
      throw error;
    }
  }




  async setPasswordAdmin(token: string, newPassword: string) {
    try {
      console.log('token', token, newPassword);
      if (!token) {
        throw new BadRequestException('Please provide a valid token'); // translation required
      }
      const decoded = this.jwtService.verify(token, {
        secret: this.configService.get<string>('jwtSecretKey'),
        
      });
      
      

      if (decoded.action !== ActionsJwt.ResetPassword) {
        throw new BadRequestException('token_is_invalid'); // translation required
      }

      const user = await this.adminRepository.findOneBy({ id: decoded.userId });

      if (decoded.password !== user.password) {
        throw new BadRequestException('token_expired');
      }

      const hashedPassword = await this.hashData(newPassword);

      if (decoded.role === Role.Admin || decoded.role === Role.SubAdmin) {
        user.status = AdminStatus.Active;
      }

      Object.assign(user, { password: hashedPassword });
      await this.adminRepository.save(user);
      return {
        status: 'success',
        message: 'password_changed',
        token
      };
    } catch (error) {
      if (error && error.name === 'TokenExpiredError')
        throw new BadRequestException('token_expired');
      if (error && error.name === 'JsonWebTokenError')
        throw new BadRequestException('パスワード再設定に失敗しました。もう一度お試しください。');
      throw error;
    }
  }




  async getResident() {
    try {
      return this.resident
    } catch (error) {
      throw error;
    }
  }



  async userCheckEmail(email: string) {
    try {
      const user = await this.usersService.findByEmail(email);
      if (!user) {
        throw new NotFoundException('Email does not exists');
      }
      if (user.active === true) {
        return {
          status: 'success',
          message: 'email is already in active state',
          isactive: true,
        };
      } else if (user.active === false) {
        return {
          status: 'success',
          message: 'email is not in active state',
          isactive: false,
        };
      }
    } catch (error) {
      throw error;
    }
  }




  async resetPassword(token: string, newPassword: string) {
    try {
      if (!token) {
        throw new BadRequestException('Please provide a valid token');
      }
      const decoded = this.jwtService.verify(token, {
        // secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
        secret: this.configService.get<string>('jwtSecretKey'),
      });
      // console.log('decoded', decoded);
      // return this.userRepository.update({ id }, password: newPassword);
      if (decoded.action !== ActionsJwt.ResetPassword) {
        throw new BadRequestException('Token is invalid');
      }
      const hashedPassword = await this.hashData(newPassword);
      const user = await this.userRepository.findOneBy({ id: decoded.userId });
      if (!user) {
        throw new NotFoundException('User account has been deleted');
      }
      if (user && user.active === false) {
        throw new NotFoundException('User has been suspended');
      }
      // if (!user) {
      //   throw new NotFoundException('user not found');
      // }
      Object.assign(user, { password: hashedPassword });
      await this.userRepository.save(user);
      return {
        status: 'success',
        message: 'Password Reset successfull',
      };
    } catch (error) {
      console.log(error);
      if (error && error.name === 'TokenExpiredError')
        throw new BadRequestException('Your Supplied token has expired');
      if (error && error.name === 'JsonWebTokenError')
        throw new BadRequestException('Your Supplied token is invalid');
    }
  }

  async accountDeleteWeb(data:AuthDto) {
    const user = await this.usersService.findByEmail(data.email);
    if (!user) throw new BadRequestException('dialog_wrong_mail_or_pwd');
    if (user.active === false) {
      throw new NotFoundException('User is in suspended state');
    }
    // Check password matches
    const passwordMatches = await argon2.verify(user.password, data.password);
    if (!passwordMatches)
      throw new BadRequestException('dialog_wrong_mail_or_pwd');

    //delete user
    const id = user.id
    this.userRepository.softDelete({ id });
    return {
      status: 'success',
      message: 'account_deleted',
    };
  }



}

enum ActionsJwt {
  SetPassword = 'set-password',
  ResetPassword = 'reset-password',
  ChangePassword = 'change-password',
  OtpHash = 'Otp-hashString',
}
