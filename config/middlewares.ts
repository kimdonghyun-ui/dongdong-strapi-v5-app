export default [
  // 📄 요청/응답 로그 출력
  "strapi::logger",

  // ❗ 에러 핸들링 (HTTP 에러 응답 관리)
  "strapi::errors",

  // 🔐 보안 관련 기본 미들웨어 (보안 헤더 등)
  "strapi::security",

  // 🌍 CORS 설정
  {
    name: "strapi::cors",
    config: {
      origin: [
        /^https:\/\/.*\.dongdong-ui\.com$/, // *.dongdong-ui.com 서브도메인 전체 허용
        "http://localhost:3000",
      ],
      credentials: true,
    },
  },

  // 🔍 쿼리 파싱 및 처리
  "strapi::query",

  // 📦 요청 바디(JSON 등) 파싱
  "strapi::body",

  // 🗂️ 세션 관련 처리 (내부용)
  "strapi::session",

  // 🖼️ 파비콘 처리
  "strapi::favicon",

  // 📁 public 폴더 정적 파일 제공
  "strapi::public",

  // 🏷️ X-Powered-By 헤더 추가
  "strapi::poweredBy",
];
