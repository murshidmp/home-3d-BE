import { Injectable } from '@nestjs/common';
import { CreateAdminDto } from './dto/create-admin.dto';
import { UpdateAdminDto } from './dto/update-admin.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Admin } from './entities/admin.entity';
import { Repository, UpdateResult } from 'typeorm';
@Injectable()
export class AdminService {
  constructor(
    @InjectRepository(Admin, 'main')
    private readonly adminRepository: Repository<Admin>,
  ) {}
  async checkAdminExistence(email: string): Promise<boolean> {
    try {
      const user = await this.adminRepository.findOneBy({ email });
      return !!user;
    
    }
    catch (err) {
      throw err;
    }
  }

  async findById(id: number): Promise<Admin> {
    return this.adminRepository.findOne({ where: { id } });
  }

  async update(id: number, updateAdminDto: UpdateAdminDto,
  ): Promise<UpdateResult> {
    return this.adminRepository.update({ id }, updateAdminDto);
  }

  async findByEmail(email: string): Promise<Admin> {
    return this.adminRepository.findOne({ where: { email } });
  }

  async create(createAdminDto: CreateAdminDto): Promise<Admin> {
    const createdAdmin = this.adminRepository.create(createAdminDto);
    return this.adminRepository.save(createdAdmin);
  }
}
