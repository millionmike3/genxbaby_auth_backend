import {
  Controller,
  Post,
  Get,
  Body,
  Req,
  Res,
  UseGuards,
  UnauthorizedException
} from "@nestjs/common";

import { Request, Response } from "express";
import { ConfigService } from "@nestjs/config";

import { AuthService } from "./auth.service";
import { LoginDto } from "./dto/login.dto";
import { RegisterDto } from "./dto/register.dto";
import { JwtAuthGuard } from "./guards/jwt-auth.guard";

@Controller("auth")
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService
  ) {}

  private cookieOptions() {
    const secure =
      this.config.get<string>("COOKIE_SECURE") === "true";

    const sameSite =
      (this.config.get<string>("COOKIE_SAME_SITE") || "lax") as
        "strict" | "lax" | "none";

    return {
      httpOnly: true,
      secure,
      sameSite,
      domain: this.config.get<string>("COOKIE_DOMAIN") || undefined,
      path: "/auth",
      maxAge:
        Number(this.config.get<string>("REFRESH_TOKEN_DAYS") || 30) *
        24 * 60 * 60 * 1000
    };
  }

  private cookieName(): string {
    return this.config.get<string>("COOKIE_NAME") || "genxbaby_refresh";
  }

  @Post("register")
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post("login")
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) response: Response
  ) {
    const result = await this.authService.login(dto);

    response.cookie(
      this.cookieName(),
      result.refreshToken,
      this.cookieOptions()
    );

    const { refreshToken, ...publicResult } = result;

    return publicResult;
  }

  @Post("refresh")
  async refresh(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response
  ) {
    const rawToken = request.cookies?.[this.cookieName()];

    if (!rawToken) {
      throw new UnauthorizedException("Refresh token required");
    }

    const result = await this.authService.refresh(rawToken);

    response.cookie(
      this.cookieName(),
      result.refreshToken,
      this.cookieOptions()
    );

    const { refreshToken, ...publicResult } = result;

    return publicResult;
  }

  @Post("logout")
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response
  ) {
    await this.authService.logout(
      request.cookies?.[this.cookieName()]
    );

    response.clearCookie(
      this.cookieName(),
      this.cookieOptions()
    );

    return { message: "Logged out successfully" };
  }

  @Get("me")
  @UseGuards(JwtAuthGuard)
  me(@Req() request: Request & {
    user: { userId: number; role: string };
  }) {
    return this.authService.getProfile(request.user.userId);
  }
}