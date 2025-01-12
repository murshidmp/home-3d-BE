import * as nodemailer from 'nodemailer';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { MailService } from '@sendgrid/mail';




@Injectable()
export class EmailService {
  constructor(private configService: ConfigService) { }

  newTransport() {
    return nodemailer.createTransport({
      host: 'smtp.sendgrid.net',
      port: 587,
      auth: {
        user: 'apikey',
        pass: this.configService.get('sengdrid.apiKey'),
      },
    });
  }
  async send(toMail: string, subject: string, token: string, path: string) {
    try {
      const baseURL = this.configService.get('BASE_URL')
      // Define email options
      const mailOptions = {
        from: this.configService.get('SENDER_EMAIL'),
        to: toMail,
        subject: subject,
        html: baseURL + path + token,
      };
      // Create a transport and send email
      await this.newTransport().sendMail(mailOptions);
    } catch (error) {
      throw error;
    }
  }

  async sendEmail(to: string, templateId: string, dynamicTemplateData: any, subject: string) {
    const sendgridApiKey = this.configService.get('sendgrid.apiKey');
    const mailService = new MailService();

    mailService.setApiKey(sendgridApiKey);

    const msg = {
      to,
      from: this.configService.get('SENDER_EMAIL'),
      subject,
      templateId,
      dynamicTemplateData,
    };

    try {
      await mailService.send(msg);
    } catch (error) {
      console.error('Error sending email:', error);
      throw new Error('Failed to send email');
    }
  }

}
