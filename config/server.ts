export default ({ env }) => ({
  host: env('HOST', '0.0.0.0'),
  port: env.int('PORT', 1337),

  // 🔑 Cloudtype / 프록시 환경에서 HTTPS 인식하도록 설정
  proxy: true,

  app: {
    keys: env.array('APP_KEYS'),
  },
});
