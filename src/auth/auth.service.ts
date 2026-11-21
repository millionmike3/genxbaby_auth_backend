import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  ForbiddenException
} from "@nestjs/common";

import { ConfigService } from "@nestjs/config";
import { PrismaService } from "../prisma/prisma.service";

import {
  UserRole,
  UserStatus
} from "@prisma/client";

import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";

import { LoginDto } from "./dto/login.dto";
import { RegisterDto } from "./dto/register.dto";

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService
  ) {}

  private get accessSecret(): string {
    const secret = this.config.getOrThrow<string>("JWT_SECRET");

    if (secret.length < 32) {
      throw new Error("JWT_SECRET must contain at least 32 characters");
    }

    return secret;
  }

  private hashToken(token: string): string {
    return crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");
  }

  private createAccessToken(userId: number, role: UserRole): string {
    return jwt.sign(
      {
        role,
        typ: "access"
      },
      this.accessSecret,
      {
        algorithm: "HS256",
        subject: String(userId),
        expiresIn: (this.config.get<string>("JWT_ACCESS_TTL") || "15m") as jwt.SignOptions["expiresIn"],
        issuer: this.config.get<string>("JWT_ISSUER") || "genxbaby-auth",
        audience: this.config.get<string>("JWT_AUDIENCE") || "genxbaby-frontend"
      }
    );
  }

  private createRefreshToken(): string {
    return crypto.randomBytes(48).toString("base64url");
  }

  private refreshExpiry(): Date {
    const days = Number(
      this.config.get<string>("REFRESH_TOKEN_DAYS") || 30
    );

    return new Date(
      Date.now() + days * 24 * 60 * 60 * 1000
    );
  }

  private async audit(
    eventType: string,
    userId?: number,
    email?: string
  ) {
    try {
      await this.prisma.authAuditEvent.create({
        data: {
          eventType,
          userId,
          email
        }
      });
    } catch (error) {
      console.error("Authentication audit write failed", error);
    }
  }

  async register(dto: RegisterDto) {
    const email = dto.email.toLowerCase().trim();

    const existing = await this.prisma.user.findUnique({
      where: { email }
    });

    if (existing) {
      throw new ConflictException(
        "An account with this email already exists"
      );
    }

    const rounds = Number(
      this.config.get<string>("BCRYPT_ROUNDS") || 12
    );

    const passwordHash = await bcrypt.hash(
      dto.password,
      rounds
    );

    const user = await this.prisma.user.create({
      data: {
        email,
        username: dto.username?.trim(),
        passwordHash,
        role: UserRole.BORROWER,
        status: UserStatus.ACTIVE
      },
      select: {
        id: true,
        email: true,
        username: true,
        role: true,
        status: true,
        createdAt: true
      }
    });

    await this.audit("REGISTER_SUCCESS", user.id, user.email);

    return { user };
  }

  async login(dto: LoginDto) {
    const email = dto.email.toLowerCase().trim();

    const user = await this.prisma.user.findUnique({
      where: { email }
    });

    if (!user || !user.passwordHash) {
      await this.audit("LOGIN_FAILED", undefined, email);

      throw new UnauthorizedException(
        "Invalid email or password"
      );
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new ForbiddenException(
        "Account temporarily locked"
      );
    }

    if (user.status !== UserStatus.ACTIVE) {
      throw new ForbiddenException(
        "Account is not active"
      );
    }

    const valid = await bcrypt.compare(
      dto.password,
      user.passwordHash
    );

    if (!valid) {
      const attempts = user.failedLoginAttempts + 1;

      const maxAttempts = Number(
        this.config.get<string>("MAX_LOGIN_ATTEMPTS") || 5
      );

      const lockoutMinutes = Number(
        this.config.get<string>("LOCKOUT_MINUTES") || 15
      );

      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts:
            attempts >= maxAttempts ? 0 : attempts,

          lockedUntil:
            attempts >= maxAttempts
              ? new Date(Date.now() + lockoutMinutes * 60 * 1000)
              : null
        }
      });

      await this.audit("LOGIN_FAILED", user.id, user.email);

      throw new UnauthorizedException(
        "Invalid email or password"
      );
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lockedUntil: null,
        lastLoginAt: new Date()
      }
    });

    const refreshToken = this.createRefreshToken();

    await this.prisma.authToken.create({
      data: {
        userId: user.id,
        tokenHash: this.hashToken(refreshToken),
        type: "REFRESH",
        expiresAt: this.refreshExpiry()
      }
    });

    await this.audit("LOGIN_SUCCESS", user.id, user.email);

    return {
      accessToken: this.createAccessToken(user.id, user.role),
      refreshToken,
      tokenType: "Bearer",
      expiresIn: this.config.get<string>("JWT_ACCESS_TTL") || "15m",
      role: user.role,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role
      }
    };
  }

  async refresh(rawToken: string) {
    if (!rawToken || rawToken.length < 40) {
      throw new UnauthorizedException("Refresh token required");
    }

    const tokenHash = this.hashToken(rawToken);
    const now = new Date();

    const result = await this.prisma.$transaction(async tx => {
      const stored = await tx.authToken.findUnique({
        where: { tokenHash }
      });

      if (
        !stored ||
        stored.type !== "REFRESH" ||
        stored.consumedAt ||
        stored.expiresAt <= now
      ) {
        return null;
      }

      const user = await tx.user.findUnique({
        where: { id: stored.userId }
      });

      if (!user || user.status !== UserStatus.ACTIVE) {
        return null;
      }

      const consumed = await tx.authToken.updateMany({
        where: {
          id: stored.id,
          consumedAt: null,
          expiresAt: { gt: now }
        },
        data: {
          consumedAt: now
        }
      });

      if (consumed.count !== 1) {
        return null;
      }

      const nextRefreshToken = this.createRefreshToken();

      await tx.authToken.create({
        data: {
          userId: user.id,
          tokenHash: this.hashToken(nextRefreshToken),
          type: "REFRESH",
          expiresAt: this.refreshExpiry()
        }
      });

      return {
        user,
        nextRefreshToken
      };
    });

    if (!result) {
      throw new UnauthorizedException(
        "Refresh token is invalid or expired"
      );
    }

    await this.audit(
      "TOKEN_REFRESH",
      result.user.id,
      result.user.email
    );

    return {
      accessToken: this.createAccessToken(
        result.user.id,
        result.user.role
      ),
      refreshToken: result.nextRefreshToken,
      tokenType: "Bearer",
      expiresIn: this.config.get<string>("JWT_ACCESS_TTL") || "15m",
      role: result.user.role
    };
  }

  async logout(rawToken?: string) {
    if (rawToken) {
      await this.prisma.authToken.updateMany({
        where: {
          tokenHash: this.hashToken(rawToken),
          type: "REFRESH",
          consumedAt: null
        },
        data: {
          consumedAt: new Date()
        }
      });
    }

    return { message: "Logged out successfully" };
  }

  async getProfile(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        username: true,
        phone: true,
        role: true,
        status: true,
        createdAt: true,
        lastLoginAt: true
      }
    });

    if (!user || user.status !== UserStatus.ACTIVE) {
      throw new UnauthorizedException("Account unavailable");
    }

    return { user };
  }
}
