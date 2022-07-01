import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import jwt from 'express-jwt';
import { ConfigService } from '@nestjs/config';
import { expressJwtSecret } from 'jwks-rsa';
import { promisify } from 'util';
import { GqlExecutionContext } from '@nestjs/graphql';

@Injectable()
export class AuthorizationGuard implements CanActivate {
  private AUTHO_AUDIENCE: string;
  private AUTHO_DOMAIN: string;

  constructor(private configServer: ConfigService) {
    this.AUTHO_AUDIENCE = this.configServer.get('AUTHO_AUDIENCE') ?? '';
    this.AUTHO_DOMAIN = this.configServer.get('AUTHO_DOMAIN') ?? '';
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const { req, res } = GqlExecutionContext.create(context).getContext();

    const checkJWT = promisify(
      jwt({
        secret: expressJwtSecret({
          cache: true,
          rateLimit: true,
          jwksRequestsPerMinute: 5,
          jwksUri: `${this.AUTHO_DOMAIN}.well-known/jwks.json`,
        }),
        audience: this.AUTHO_AUDIENCE,
        issuer: this.AUTHO_DOMAIN,
        algorithms: ['RS256'],
      }),
    );

    try {
      await checkJWT(req, res);

      return true;
    } catch (err) {
      throw new UnauthorizedException(err);
    }
  }
}
