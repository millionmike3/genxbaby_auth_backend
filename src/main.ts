import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { AppModule } from "./app.module";
import { HttpExceptionFilter } from "./common/filters/http-exception.filter";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const config = app.get(ConfigService);

  app.use(helmet());
  app.use(cookieParser());

  const origins = (config.get<string>("CORS_ORIGINS") || "")
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean);

  app.enableCors({
    origin: origins,
    credentials: true
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true
    })
  );

  app.useGlobalFilters(new HttpExceptionFilter());

  app.enableShutdownHooks();

  const port = config.get<number>("PORT") || 8080;

  await app.listen(port, "0.0.0.0");

  console.log(`GenXBaby NestJS Auth listening on port ${port}`);
}

bootstrap();