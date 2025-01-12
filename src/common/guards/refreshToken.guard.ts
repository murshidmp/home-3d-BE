import { ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class RefreshTokenGuard extends AuthGuard('jwt-refresh') {
    handleRequest(err, user, info) {

        // If there's an error or if user is falsy (invalid or expired token), throw a ForbiddenException with a 403 status code.
        if (err || !user) {
            throw new ForbiddenException('Invalid or expired refresh token', 'custom-error-key');
        }
        return user;
    }
}
