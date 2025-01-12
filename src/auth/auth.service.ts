import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  HttpStatus,
  NotFoundException,
  UnauthorizedException
} from '@nestjs/common';
import * as SendGrid from '@sendgrid/mail';
import { UsersService } from 'src/user/users.service';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthDto } from './dto/auth.dto';
import { User } from '../user/entities/user.entity';
import { Admin, AdminStatus } from '../admin/entities/admin.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { DeleteResult, In, Repository, UpdateResult } from 'typeorm';
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
import { CreateUserDto } from 'src/user/dto/create-user.dto';

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
      // Check password matches
      const passwordMatches = await argon2.verify(user.password, data.password);
      if (!passwordMatches)
        throw new BadRequestException('dialog_wrong_mail_or_pwd');

      // Generate tokens
      const tokens = await this.getTokens(user.id, user.email, Role.User);
      const refreshToken = tokens.refreshToken;

      // Update refresh tokens
      await this.updateRefreshToken(user.id, refreshToken);

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
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

  async forgotPasswordUser(email: string) {
    try {
      // check if the provided email is registered with any user
      const user = await this.userRepository.findOneBy({ email });
      if (!user) {
        throw new BadRequestException({
          status: 'error',
          message: 'Email is not registered'
        });
      }
      const token = await this.jwtService.signAsync(
        {
          userId: user.id,
          action: ActionsJwt.ResetPassword,
          password: user.password,
          role: Role.User,
        },
        {
          secret: this.configService.get<string>('jwtSecretKey'),
          expiresIn: '24h',
        },
      );

      const emailTemplateData = {
        passwordResetLink: this.configService.get('userApHost') + 'reset-password?token=' + token
      };

      const emailTemplateId = EmailTemplate.ResetPasswordUser;
      const subject = 'Reset Password';

      const emailResponse = await this.emailService.sendEmail(
        user.email,
        emailTemplateId,
        emailTemplateData,
        subject,
      );

      const encriptedToken = await argon2.hash(token);
      user.resetPasswordToken = encriptedToken;
      await this.userRepository.save(user);

      if (emailResponse[0]?.statusCode !== 202) {
        throw new BadRequestException('Email could not be sent');
      }

      return {
        status: true,
        message: 'pwd_reset_url_sent',
        token: token,
      };
    } catch (error) {
      throw error;
    }
  }

  async resetPasswordUser(token: string, newPassword: string) {
    try {
      if (!token) {
        throw new BadRequestException('Please provide a valid token');
      }
      const decoded = this.jwtService.verify(token, {
        secret: this.configService.get<string>('jwtSecretKey'),
      });
      if (decoded.action !== ActionsJwt.ResetPassword) {
        throw new BadRequestException('Token is invalid');
      }
      const user = await this.userRepository.findOneBy({ id: decoded.userId });
      if (!user) {
        throw new NotFoundException('User account has been deleted');
      }
      const tokenMatches = await argon2.verify(user.resetPasswordToken, token);
      if (!tokenMatches) {
        throw new BadRequestException('Token is invalid');
      }
      const hashedPassword = await this.hashData(newPassword);
      user.password = hashedPassword;
      user.resetPasswordToken = null;
      await this.userRepository.save(user);

      return {
        status: true,
        message: 'Password Reset successful',
      };
    } catch (error) {
      if (error && error.name === 'TokenExpiredError')
        throw new BadRequestException('Your Supplied token has expired');
      if (error && error.name === 'JsonWebTokenError')
        throw new BadRequestException('Your Supplied token is invalid');
      throw error;
    }
  }

  async changePasswordUser(
    userId: string,
    changePasswordDto: ChangePasswordDto,
  ) {
    try {
      const { oldPassword, newPassword } = changePasswordDto;
      const user = await this.userRepository.findOneBy({
        id: userId,
      });
      if (!user) {
        throw new NotFoundException('User not found');
      }
      if (!(await argon2.verify(user.password, oldPassword))) {
        throw new BadRequestException(
          'Please provide the correct current password',
        );
      }
      const hashedNewPassword = await this.hashData(newPassword);
      user.password = hashedNewPassword;
      await this.userRepository.save(user);
      return {
        status: 'success',
        message: 'Password successfully changed',
      };
    } catch (error) {
      throw error;
    }
  }

  async userLogout(userId: string) {
    await this.userRepository.update(userId, { refreshToken: null });
  }

  async userRefreshTokens(userId: string, refreshToken: string) {
    try {
      const user = await this.userRepository.findOne({
        where: { id: userId },
      });
      if (!user || !user.refreshToken)
        throw new ForbiddenException('Access Denied');
      const refreshTokenMatches = await argon2.verify(
        user.refreshToken,
        refreshToken,
      );
      if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');
      const tokens = await this.getTokens(user.id, user.email, Role.User);
      tokens.refreshToken = refreshToken;
      return tokens;
    } catch (error) {
      throw error;
    }
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    try {
      const hashedRefreshToken = await this.hashData(refreshToken);
      await this.userRepository.update(userId, {
        refreshToken: hashedRefreshToken
      });
    } catch (error) {
      throw error;
    }
  }

  async getTokens(userId: string, username: string, role: string) {
    try {
      const [accessToken, refreshToken] = await Promise.all([
        this.jwtService.signAsync(
          {
            sub: userId,
            username,
            role,
          },
          {
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

  async adminSignIn(data: AdminSignInDto) {
    try {
      const user = await this.adminsService.findByEmail(data.email);
      if (!user)
        throw new BadRequestException({
          status: HttpStatus.BAD_REQUEST,
          messages: {
            email: 'dialog_wrong_mail_or_pwd',
          },
        });
      if (user.deleted === true)
        throw new BadRequestException({
          status: HttpStatus.BAD_REQUEST,
          messages: {
            user: 'dialog_wrong_mail_or_pwd',
          },
        });
      if (user.status === AdminStatus.Inactive)
        throw new BadRequestException('dialog_accnt_suspended');

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
      const userExists = await this.adminsService.findByEmail(
        CreateAdminDto.email,
      );
      if (userExists) {
        throw new BadRequestException('User already exists');
      }

      const hash = await this.hashData(CreateAdminDto.password);
      const newUser = await this.adminsService.create({
        ...CreateAdminDto,
        password: hash,
      });

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
      message: 'Logout successful',
    };
  }

  async adminPasswordChange(
    email: string,
    changePasswordDto: ChangePasswordDto,
  ) {
    try {
      const { oldPassword, newPassword } = changePasswordDto;
      const admin = await this.adminRepository.findOneBy({
        email: email,
      });
      if (!admin) {
        throw new NotFoundException('User does not exist');
      }
      if (!(await argon2.verify(admin.password, oldPassword))) {
        throw new BadRequestException({
          status: 'error',
          messages: {
            oldPassword: 'dialog_current_pwd_incorrect',
          },
        });
      }
      const hashedNewPassword = await this.hashData(newPassword);
      admin.password = hashedNewPassword;
      await this.adminRepository.save(admin);
      return {
        status: 'success',
        message: 'password_changed',
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
      const user = await this.adminsService.findByEmail(email);
      if (!user) {
        throw new BadRequestException({
          status: 'error',
          messages: {
            email: 'msg_enter_curr_email',
          },
        });
      }

      if (user.status === AdminStatus.Invited) {
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
          secret: this.configService.get<string>('jwtSecretKey'),
          expiresIn: '24h',
        },
      );

      const dynamicTemplateData = {
        passwordResetLink: this.configService.get('adminHost') + 'auth/reset-password?token=' + token,
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
        message: 'pwd_reset_url_sent',
      };
    } catch (error) {
      throw error;
    }
  }

  async resetPasswordAdmin(token: string, newPassword: string) {
    try {
      if (!token) {
        throw new BadRequestException('Please provide a valid token');
      }
      const decoded = this.jwtService.verify(token, {
        secret: this.configService.get<string>('jwtSecretKey'),
      });

      if (decoded.action !== ActionsJwt.ResetPassword) {
        throw new BadRequestException('token_is_invalid');
      }

      const user = await this.adminRepository.findOneBy({ id: decoded.userId });

      if (decoded.password !== user.password) {
        throw new BadRequestException('token_expired');
      }
      if (decoded.status !== AdminStatus.Active) {
        throw new BadRequestException('お使いのアカウントは現在一時停止中です。パスワードの再設定には、担当の管理者までお知らせください。');
      }

      const hashedPassword = await this.hashData(newPassword);

      if (decoded.role === Role.Admin) {
        user.status = AdminStatus.Active;
      }

      user.password = hashedPassword;
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
      if (!token) {
        throw new BadRequestException('Please provide a valid token');
      }
      const decoded = this.jwtService.verify(token, {
        secret: this.configService.get<string>('jwtSecretKey'),
      });

      if (decoded.action !== ActionsJwt.ResetPassword) {
        throw new BadRequestException('token_is_invalid');
      }

      const user = await this.adminRepository.findOneBy({ id: decoded.userId });

      if (decoded.password !== user.password) {
        throw new BadRequestException('token_expired');
      }

      const hashedPassword = await this.hashData(newPassword);

      if (decoded.role === Role.Admin || decoded.role === Role.SubAdmin) {
        user.status = AdminStatus.Active;
      }

      user.password = hashedPassword;
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

  async updateAdminRefreshToken(userId: number, refreshToken: string) {
    try {
      const admin = await this.adminRepository.findOne({
        where: { id: userId, status: In([AdminStatus.Active, AdminStatus.Invited]) },
      });
      if (!admin) throw new ForbiddenException('Access Denied');
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
}

enum ActionsJwt {
  SetPassword = 'set-password',
  ResetPassword = 'reset-password',
  ChangePassword = 'change-password',
  OtpHash = 'Otp-hashString',
}