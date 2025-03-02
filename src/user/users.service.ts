import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import * as argon2 from 'argon2';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) { }

  async checkUserExistence(email: string): Promise<boolean> {
    email = email.toLowerCase();
    const user = await this.userRepository.findOneBy({ email });
    return !!user;
  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    const user = this.userRepository.create(createUserDto);
    return await this.userRepository.save(user);
  }

  async update(userId: number, updateUserDto: UpdateUserDto): Promise<User> {
    await this.userRepository.update(userId, updateUserDto);
    return this.findById(userId);
  }

  async updateRefreshToken(userId: number, refreshToken: string): Promise<void> {
    const hashedRefreshToken = await argon2.hash(refreshToken);
    await this.userRepository.update(userId, {
      refreshToken: hashedRefreshToken,
    });
  }

  async clearRefreshToken(userId: number): Promise<void> {
    await this.userRepository.update(userId, { refreshToken: null });
  }

  async findByEmail(email: string): Promise<User> {
    email = email.toLowerCase();
    return this.userRepository.findOne({ where: { email } });
  }

  async findById(id: number): Promise<User | null> {
    return this.userRepository.findOne({ where: { id } });
  }

  async deleteUser(userId: number): Promise<void> {
    await this.userRepository.softDelete(userId);
  }
}
