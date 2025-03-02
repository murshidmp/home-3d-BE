import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { AccessTokenGuard } from 'src/common/guards/accessToken.guard';
import { ApiBearerAuth, ApiTags, ApiResponse } from '@nestjs/swagger';
import { ApiSuccessResponse } from 'src/common/dto/api-response.dto';

@ApiTags('Users')
@ApiBearerAuth()
@UseGuards(AccessTokenGuard)
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) { }

  // Endpoint for creating a new user (if needed; sometimes registration is part of the auth module)
  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiResponse({ status: 201, description: 'User created successfully.' })
  async create(@Body() createUserDto: CreateUserDto) {
    const user = await this.usersService.create(createUserDto);
    return ApiSuccessResponse.of(user, 'User created successfully');
  }

  // Get current user's profile (e.g., /users/me)
  @Get('me')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'User profile fetched successfully.' })
  async getProfile(@Req() req: any) {
    const userId = req.user.sub;
    const user = await this.usersService.findById(userId);
    return ApiSuccessResponse.of(user, 'User profile fetched successfully');
  }

  // Update current user's profile (edit profile)
  @Patch('me')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'User profile updated successfully.' })
  async updateProfile(@Req() req: any, @Body() updateUserDto: UpdateUserDto) {
    const userId = req.user.sub;
    const updatedUser = await this.usersService.update(userId, updateUserDto);
    return ApiSuccessResponse.of(updatedUser, 'User profile updated successfully');
  }

  // Soft-delete current user's account
  @Delete('me')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'User account deleted successfully.' })
  async deleteProfile(@Req() req: any) {
    const userId = req.user.sub;
    await this.usersService.deleteUser(userId);
    return ApiSuccessResponse.of(null, 'User account deleted successfully');
  }

  // Optionally, get any user's profile by id (useful for public profiles or admin)
  @Get(':id')
  @HttpCode(HttpStatus.OK)
  @ApiResponse({ status: 200, description: 'User profile fetched successfully.' })
  async getUserById(@Param('id') id: number) {
    const user = await this.usersService.findById(id);
    return ApiSuccessResponse.of(user, 'User profile fetched successfully');
  }
}
