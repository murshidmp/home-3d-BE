


import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';

const matchRoles = (roles, userRoles) => {
  return roles.some(role => role === userRoles);
};

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    // @InjectRepository(Admin)
    // private adminRepository: Repository<Admin>,
  ) { }

  // async canActivate(context: ExecutionContext): Promise<boolean> {
   canActivate(context: ExecutionContext): boolean {
    const roles = this.reflector.get<string[]>('roles', context.getHandler());
    if (!roles) {
      return true;
    }
    const req = context.switchToHttp().getRequest() as any;

    /* Added to check whether the user is suspended 
    ( exmaple if subadmin is suspended by Admin while subadmin is logged in;
      Then need to prevent the access apis till the supplied access token expires ) */
    
    // const adminUser = await this.adminRepository.findOne({ where: { id: req.user['sub'] } });
    // if (!adminUser) {
    //   return false;
    // }
    // if (adminUser.status === 'inactive') {
    //   return false;
    // }
    
    const user = req.user;
    return matchRoles(roles, user.role);
  }
}