import { Injectable, Logger } from '@nestjs/common';
import { Express } from 'express';
import { Readable } from 'stream';

import {
  S3Client,
  PutObjectCommand,
  PutObjectCommandInput,
  PutObjectCommandOutput,
  GetObjectCommand,
  GetObjectCommandInput,
  GetObjectCommandOutput,
  CopyObjectCommand,
  DeleteObjectCommand,
  DeleteObjectCommandInput,
  DeleteObjectsCommand
} from '@aws-sdk/client-s3';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class S3Service {
  private region: string;
  private s3: S3Client;
  private logger = new Logger(S3Service.name);
  private bucketName;

  constructor(private configService: ConfigService) {
    this.region = this.configService.get<string>('awsSecrets.region') || 'ap-northeast-1';
    this.s3 = new S3Client({
      // region: this.region,
      credentials: {
        accessKeyId: this.configService.get('awsSecrets.accessKeyId'),
        secretAccessKey: this.configService.get('awsSecrets.secretAccessKey'),
      },

      region: this.configService.get('awsSecrets.region'),
    });
    this.bucketName = this.configService.get<string>('awsSecrets.bucketName');
  }

  // async uploadFile(file: Express.Multer.File, key: string) {
    
  //   // const bucket = 'hi-touch-assets-prod'; //this.configService.get<string>('AWS_BUCKET_NAME');
  //   const input: PutObjectCommandInput = {
  //     Body: file.buffer,
  //     Bucket: this.bucketName,
  //     Key: key,
  //     ContentType: file.mimetype,
  //     // ACL: 'public-read',
  //   };
  //   try {
  //     const response: PutObjectCommandOutput = await this.s3.send(
  //       new PutObjectCommand(input),
  //     );
  //     // console.log('response from s3', response);
  //     if (response.$metadata.httpStatusCode === 200) {
  //       return `https://${this.bucketName}.s3.${this.region}.amazonaws.com/${key}`;
  //     }
  //     throw new Error('Image not saved in s3!');
  //   } catch (err) {
  //     this.logger.error('Cannot save file to s3,', err);
  //     throw err;
  //   }
  // }

  async copyFileInS3(sourceKey: string, destinationKey: string,) {


    const copySource = `/${this.bucketName}/${sourceKey}`;
    const destinationObjectKey = destinationKey

    const copyParams = {
      Bucket: this.bucketName,
      CopySource: copySource,
      Key: destinationObjectKey,
    };

    try {
      console.log("this is copyyy file");

      await this.s3.send(new CopyObjectCommand(copyParams));
      return `https://${this.bucketName}.s3.${this.region}.amazonaws.com/${destinationKey}.`;
    } catch (error) {
      this.logger.error('Failed to copy file in S3:', error);
      throw error;
    }
  }

  async deleteFileInS3(key: string) {
    // const bucketName = 'hi-touch-assets-prod';
    const deleteParams : DeleteObjectCommandInput = {
      Bucket: this.bucketName,
      Key: key,
    };

    try {
      await this.s3.send(new DeleteObjectCommand(deleteParams));
      return true;
    } catch (error) {
      this.logger.error('Failed to delete file in S3:', error);
      throw error;
    }
  }

  async deleteMultipleFilesInS3(keys: string[]) {
    // const bucketName = 'hi-touch-assets-prod';
    const deleteParams = {
      Bucket: this.bucketName,
      Delete: {
        Objects: keys.map(key => ({ Key: key })),
        Quiet: false,
      },
    };

    try {
      if (keys.length === 0) {
        return true;
      }
      const delResponse =await this.s3.send(new DeleteObjectsCommand(deleteParams));
      // console.log('delResponse', delResponse);
      return true;
    } catch (error) {
      this.logger.error('Failed to delete file in S3:', error);
      throw error;
    }
  }

  async downloadFile(key: string) {
    // const bucket = this.configService.get<string>('AWS_BUCKET_NAME');
    const input: GetObjectCommandInput = {
      Bucket: this.bucketName,
      Key: key,
    };
    try {
      // console.log('hi');
      const response: GetObjectCommandOutput = await this.s3.send(
        new GetObjectCommand(input),
      );
      // console.log('response from s3', response);
      return response;
    } catch (err) {
      this.logger.error('Cannot read file from s3,', err);
      throw err;
    }
  }

  async streamFileFromS3(bucketName: string, key: string): Promise<Readable> {
    const params = {
      Bucket: bucketName,
      Key: key,
    };

    // const s3Object = await this.s3.getObject(params).promise();
    const s3Obj = await this.s3.send(new GetObjectCommand(params));
    const fileStream = new Readable();
    fileStream.push(s3Obj.Body);
    fileStream.push(null);

    return fileStream;
  }
}
