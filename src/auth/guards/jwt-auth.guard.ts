import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException
} from "@nestjs/common";

import { ConfigService } from "@nestjs/config";
import { UserRole } from "@prisma/client";
import jwt from "jsonwebtoken";

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const header = request.headers.authorization;

    if (!header?.startsWith("Bearer ")) {
      throw new UnauthorizedException("Access token required");
    }

    const token = header.substring(7);

    try {
      const secret = this.config.getOrThrow<string>("JWT_SECRET");

      if (secret.length < 32) {
        throw new Error("JWT_SECRET must contain at least 32 characters");
      }

      const payload = jwt.verify(token, secret, {
        algorithms: ["HS256"],
        issuer: this.config.get<string>("JWT_ISSUER") || "genxbaby-auth",
        audience: this.config.get<string>("JWT_AUDIENCE") || "genxbaby-frontend"
      }) as jwt.JwtPayload & {
        role: UserRole;
        typ: string;
      };

      const userId = Number(payload.sub);

      if (
        !Number.isInteger(userId) ||
        userId <= 0 ||
        payload.typ !== "access" ||
        !Object.values(UserRole).includes(payload.role)
      ) {
        throw new UnauthorizedException("Invalid access token");
      }

      request.user = {
        userId,
        role: payload.role
      };

      return true;
    } catch {
      throw new UnauthorizedException(
        "Invalid or expired access token"
      );
    }
  }
}
