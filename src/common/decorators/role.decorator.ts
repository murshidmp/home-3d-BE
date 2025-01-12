import { SetMetadata } from '@nestjs/common';

export const WithRoles = (...roles: string[]) => SetMetadata('roles', roles);