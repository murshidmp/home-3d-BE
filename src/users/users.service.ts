import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectRepository,  } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User, 'main')
    private readonly userRepository: Repository<User>,
  ) { }
  async checkUserExistence(email: string): Promise<boolean> {
    try {
      email = email.toLowerCase();
      const user = await this.userRepository.findOneBy({ email });
      return !!user;
    
    }
    catch (err) {
      throw err;
    }
  }
  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const user = this.userRepository.create(createUserDto);
      return await this.userRepository.save(user);
    } catch (err) {
      throw err;
    }
  }

  async findByEmail(email: string): Promise<User> {
    try {
      email = email.toLowerCase();
      return this.userRepository.findOne({ where: { email } });
    }
    catch (err) {
      throw err;
    }
  }

}
