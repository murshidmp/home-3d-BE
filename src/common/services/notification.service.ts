// import { Global, Injectable, Module } from '@nestjs/common';
// // import {
// //   initializeApp,
// //   credential,
// //   messaging,
// //   ServiceAccount,
// // } from 'firebase-admin';
// import * as firebase from 'firebase-admin';

// import {
//   Message,
//   MulticastMessage,
// } from 'firebase-admin/lib/messaging/messaging-api';

// import { ConfigService } from '@nestjs/config';

// @Injectable()
// export class NotificationService {
//   // private firebaseApp: admin.app.App;
//   constructor(private configService: ConfigService) {
//     // console.log('creating notification');

//     // // this.firebaseApp =
//     firebase.initializeApp({
//       credential: firebase.credential.cert({
//         projectId: this.configService.get<string>('FIREBASE_PROJECT_ID'),
//         clientEmail: this.configService.get<string>('FIREBASE_CLIENT_EMAIL'),
//         privateKey: this.configService
//           .get<string>('FIREBASE_PRIVATE_KEY')
//           .replace(/\\n/g, '\n'),
//       }),
//     });
//   }

//   async sendNotification(message: Message, dryRun: boolean = false) {
//     try {
//       const msgResponse = await firebase.messaging().send(message, dryRun);
//       // console.log('msgResponse', msgResponse);
//       return msgResponse;
//     } catch (error) {
//       console.log(error);
//     }
//     // this.firebaseInitiateApp();

//   }

//   async sendNotificationToMultipleDevices(message: MulticastMessage) {
//     try {
//       const msgResponse = await firebase
//         .messaging()
//         .sendEachForMulticast(message);
//       // console.log('msgResponse', msgResponse);
//       return msgResponse;
//     } catch (error) {
//       console.log(error);
//     }
//   }

//   async firebaseInitiateApp() {
//     try {
//       firebase.initializeApp({
//         credential: firebase.credential.cert({
//           projectId: this.configService.get<string>('FIREBASE_PROJECT_ID'),
//           clientEmail: this.configService.get<string>('FIREBASE_CLIENT_EMAIL'),
//           privateKey: this.configService
//             .get<string>('FIREBASE_PRIVATE_KEY')
//             .replace(/\\n/g, '\n'),
//         }),
//       });
//     } catch (error) {
//       console.log(error);

//     }
//   }

// }
// @Global()
// @Module({
//   providers: [NotificationService],
//   exports: [NotificationService],
// })
// export class NotificationModule { }
