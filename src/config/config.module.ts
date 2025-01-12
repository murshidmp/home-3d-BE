import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import loadSecrets from "./config.secrets";

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({
      load: [loadSecrets],
      isGlobal: true,
    }),
  ],
})
export class CustomConfigModule {}