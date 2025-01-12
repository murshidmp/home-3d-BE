// create a guard to check if the user is deleted or not. If the user is deleted, then the user should not be able to access any of the APIs.
//The guard should be applied to all the APIs except the signup and signin APIs.

import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { InjectRepository } from '@nestjs/typeorm';
import { Admin } from 'src/admin/entities/admin.entity';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { Role } from '../enums/roles';

// const matchRoles = (roles, userRoles) => {
//   return roles.some(role => role === userRoles);
// };

@Injectable()
export class AccountDeletedGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @InjectRepository(Admin)
    private adminRepository: Repository<Admin>,
  ) { }

  // async canActivate(context: ExecutionContext): Promise<boolean> {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // const roles = this.reflector.get<string[]>('roles', context.getHandler());
    // if (!roles) {
    //   return true;
    // }
    const req = context.switchToHttp().getRequest() as any;

    /* Added to check whether the user is suspended 
    ( exmaple if subadmin is suspended by Admin while subadmin is logged in;
      Then need to prevent the access apis till the supplied access token expires ) */
    
    if (req.user.role === Role.Admin || req.user.role === Role.SubAdmin) { 
      const adminUser = await this.adminRepository.findOne({ where: { id: req.user['sub'] } });
      console.log('adminUser', adminUser)
      if (!adminUser || adminUser.deleted === true || adminUser.status === 'inactive') {
        return false;
      }
    }
    return true
    // if (req.user.role === 'user') {
    //   const user = await User.findOne({ where: { id: req.user['sub'] } });
    //   if (!user || user.deleted === true) {
    //     return false;
    //   }
    // }
    // const user = req.user;
    // return matchRoles(roles, user.role);
  }
}