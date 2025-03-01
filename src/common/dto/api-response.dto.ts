import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

/**
 * A standard structure for successful API responses.
 * 
 * @typeParam T - the type of `data` being returned in the success response.
 */
export class ApiSuccessResponse<T = any> {
  @ApiProperty({ default: true })
  success: boolean;

  @ApiPropertyOptional()
  message?: string;

  @ApiPropertyOptional()
  data?: T;

  constructor(params: { success?: boolean; message?: string; data?: T }) {
    this.success = params.success ?? true; // default to true
    this.message = params.message;
    this.data = params.data;
  }

  /**
   * Helper method to quickly build a success response.
   * 
   * @param data - the payload or data you want to return
   * @param message - an optional success message
   */
  static of<T>(data?: T, message?: string): ApiSuccessResponse<T> {
    return new ApiSuccessResponse<T>({
      success: true,
      message,
      data,
    });
  }
}
