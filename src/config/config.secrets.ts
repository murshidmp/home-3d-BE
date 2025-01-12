export default async function loadSecrets() {
  //Custom secrets loader
  return {
    port: process.env.PORT || 3000,
    databaseMain: {
      host: process.env.DB_HOST || 'localhost', //Defualt to localhost if not provided
      port: process.env.DB_PORT || 5432, // Default to 5432 if not provided
      user: process.env.DB_USERNAME || 'postgres', //Default to postgres if not provided
      password: process.env.DB_PASSWORD,
      name: process.env.DB_NAME,
    },
    redis:{
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT,
      password: process.env.REDIS_PASSWORD
    },
    awsSecrets: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      region: process.env.AWS_REGION,
      bucketName: process.env.AWS_BUCKET_NAME
    },
    cloudFront: {
      domain: process.env.CLOUD_FRONT_DOMAIN,
      privateKey: process.env.CLOUD_FRONT_PRIVATE_KEY,
      keyPairId: process.env.CLOUD_FRONT_KEY_PAIR_ID
    },
    sendGrid: {
      apiKey: process.env.SENDGRID_API_KEY
    },
    jwtSecretKeys: {
      access: process.env.JWT_ACCESS_SECRET,
      refresh: process.env.JWT_REFRESH_SECRET
    }
    //Add more secrets

  };

};