import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PublishCommand, SNSClient } from '@aws-sdk/client-sns';

import { getSignedUrl } from '@aws-sdk/cloudfront-signer';

@Injectable()
export class AWSService {
  constructor(private configService: ConfigService) {}

  async sendSMSBySNS(
    phoneNumber: string,
    message: string,
    subject: string,
  ): Promise<any> {
    const resp = await new SNSClient(
      {
      credentials: {
        accessKeyId: this.configService.get<string>('awsSecrets.accessKeyId'),
        secretAccessKey: this.configService.get<string>('awsSecrets.secretAccessKey'),
      },

      region: this.configService.get('awsSecrets.region'),
      }
    ).send(
      new PublishCommand({
        Message: message,
        PhoneNumber: phoneNumber,
        Subject: subject,
      }),
    );
    return resp;
  }

  async downloadFileFromCloudFront(
    key: string,
    expiry: string,
  ): Promise<string> {
    try {
      const cloudfrontDistributionDomain =
        this.configService.get('cloudFront.domain');
      const s3ObjectKey = key;
      const url = `${cloudfrontDistributionDomain}/${s3ObjectKey}`;
      const privateKey = this.configService.get(
        'cloudFront.privateKey',
      ).SecretString;
      const keyPairId = this.configService.get('cloudFront.keyPairId'); //"E2XB3R4WFMFPV1";
      const dateLessThan = expiry; //"2024-01-01"; // any Date constructor compatible
      const signedUrl = getSignedUrl({
        url,
        keyPairId,
        dateLessThan,
        privateKey,
      });
      return signedUrl;
    } catch (error) {
      throw error;
      // error handling.
    }
  }
}
