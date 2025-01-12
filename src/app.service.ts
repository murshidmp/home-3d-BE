import { Injectable } from '@nestjs/common';
import { LoggerService } from './logger/logger.service';

@Injectable()
export class AppService {
  constructor(private readonly logger: LoggerService) {}
  getHello(): string {
    this.logger.warn('Hello World! loggedd');
    return 'Hello World! jan 12 12:00PM';
  }
}
