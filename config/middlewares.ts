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
      /**
       * origin 옵션을 함수로 정의하여
       * 요청을 보낸 프론트엔드 도메인을 동적으로 허용/차단한다.
       */
      origin: (ctx) => {
        // 요청을 보낸 Origin (프론트 도메인)
        const origin = ctx.request.header.origin;

        /**
         * Origin 헤더가 없는 요청
         * - 서버 내부 호출
         * - 헬스 체크
         * - Strapi 내부 요청
         * → 차단할 이유가 없으므로 허용
         */
        if (!origin) return true;

        /**
         * 로컬 개발 환경 허용
         * - Next.js 개발 서버
         */
        if (origin === "http://localhost:3000") return true;

        /**
         * 운영 환경 허용 도메인
         * - https://*.dongdong-ui.com 형태의 모든 서브도메인 허용
         * - 예:
         *   https://my-budget-app.dongdong-ui.com
         *   https://my-budget-app2.dongdong-ui.com
         */
        const allowedProd = /^https:\/\/.*\.dongdong-ui\.com$/;

        // 허용된 도메인이면 true, 아니면 false
        return allowedProd.test(origin);
      },

      /**
       * credentials: true
       * - 쿠키(httpOnly refreshToken) 인증을 허용하기 위해 필수
       * - false이면 브라우저가 쿠키를 요청에 포함하지 않음
       */
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
