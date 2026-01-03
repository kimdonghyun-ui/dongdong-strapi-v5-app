import jwt from "jsonwebtoken";

/**
 * ✅ refresh 토큰을 서명/검증할 때 쓰는 비밀키
 * - access 토큰은 Strapi 기본 jwt 서비스가 내부 SECRET을 씀
 * - refresh 토큰은 우리가 직접 jwt.sign/verify 하니까
 *   별도 secret을 쓰는 구조
 * - .env에 REFRESH_JWT_SECRET 값을 꼭 두는 걸 권장
 */
const REFRESH_SECRET = process.env.REFRESH_JWT_SECRET || "change-me";

/**
 * ✅ access 토큰 만료시간
 * - 기본값 15분
 * - Strapi 기본 jwt.issue에 options로 전달
 */
const ACCESS_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES || "15m";

/**
 * ✅ refresh 토큰 만료시간
 * - 기본값 7일
 * - 우리가 jsonwebtoken.sign 할 때 expiresIn으로 사용
 */
const REFRESH_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES || "7d";

/**
 * ✅ 브라우저에 저장할 refresh 토큰 쿠키 이름
 * - 이름을 상수로 빼두면
 *   login/refresh/logout에서 동일 이름을 안정적으로 사용 가능
 */
const REFRESH_COOKIE_NAME = "refreshToken";

// 공통: 안전하게 user 객체 정리
/**
 * ✅ sanitizeUser의 목적
 * - DB에서 가져온 user 객체엔 "절대 프론트로 보내면 안 되는 값"이 섞여 있을 수 있음
 * - 특히 아래 3개는 보안상 매우 민감:
 *   1) password              : 해시값이라도 노출 금지
 *   2) resetPasswordToken    : 비밀번호 재설정용 임시 토큰
 *   3) confirmationToken     : 이메일 인증용 임시 토큰
 * - 그래서 응답으로 user를 보낼 때
 *   이 3개를 제거한 "안전한 user"만 보내기 위해 사용하는 필터 함수
 */
function sanitizeUser(user: any) {
  if (!user) return user;
  const {
    password,
    resetPasswordToken,
    confirmationToken,
    ...safeUser
  } = user;
  return safeUser;
}

export default {
  // ✅ 로그인 + refresh cookie 발급
  /**
   * ✅ customLogin이 하는 일 (큰 흐름)
   * 1) identifier(email 또는 username) + password 입력값 검사
   * 2) users-permissions 유저 테이블에서 사용자 조회
   * 3) Strapi의 validatePassword로 비밀번호 검증
   * 4) accessToken 발급 (Strapi 기본 jwt 서비스 활용)
   * 5) refreshToken 발급 (jsonwebtoken으로 직접 생성)
   * 6) refreshToken을 HttpOnly 쿠키로 저장
   * 7) 응답은 accessToken + 안전한 user만 반환
   */
  async customLogin(ctx) {
    /**
     * ✅ 클라이언트가 보내는 로그인 바디 형태
     * - identifier: email 또는 username
     * - password: 비밀번호
     */
    const { identifier, password } = ctx.request.body as {
      identifier: string;
      password: string;
    };

    // ✅ 필수값 검사
    if (!identifier || !password) {
      return ctx.badRequest("identifier, password 필수");
    }

    // 1) 유저 찾기
    /**
     * ✅ users-permissions 플러그인의 user 테이블에서 조회
     * - identifier가 email일 수도, username일 수도 있으니까 $or 조건 사용
     */
    const user = await strapi.db
      .query("plugin::users-permissions.user")
      .findOne({
        where: {
          $or: [{ email: identifier }, { username: identifier }],
        },
      });

    // ✅ 사용자가 없으면 인증 실패
    if (!user) {
      return ctx.unauthorized("잘못된 아이디/비밀번호입니다.");
    }

    // 2) 비밀번호 검증
    /**
     * ✅ Strapi가 제공하는 안정적인 비밀번호 검증 함수 사용
     * - 입력한 평문 password와 DB에 저장된 해시 password 비교
     */
    const validPassword =
      await (strapi as any).plugins["users-permissions"].services.user.validatePassword(
        password,
        user.password
      );

    // ✅ 비밀번호가 틀리면 인증 실패
    if (!validPassword) {
      return ctx.unauthorized("잘못된 아이디/비밀번호입니다.");
    }

    // 3) access token 발급 (Strapi 기본 jwt 서비스)
    /**
     * ✅ accessToken은 Strapi 기본 jwt.issue 사용
     * - user.id만 payload로 넣고
     * - 만료 시간은 ACCESS_EXPIRES_IN (기본 15m)
     * - accessToken은 "프론트 상태(Zustand 등)"에 저장하는 용도
     */
    const accessToken =
      (strapi as any).plugins["users-permissions"].services.jwt.issue(
        { id: user.id },
        { expiresIn: ACCESS_EXPIRES_IN }
      );

    // 4) refresh token 발급 (별도 secret)
    /**
     * ✅ refreshToken은 jsonwebtoken으로 직접 발급
     * - payload에 type: "refresh"를 넣어
     *   나중에 refresh API에서 "이게 진짜 refresh 용도 토큰인지" 체크 가능
     * - REFRESH_SECRET으로 서명
     * - 만료 시간은 REFRESH_EXPIRES_IN (기본 7d)
     */
    const refreshToken = jwt.sign(
      { id: user.id, type: "refresh" },
      REFRESH_SECRET as string,
      { expiresIn: REFRESH_EXPIRES_IN as string | number } as jwt.SignOptions
    );

    // 5) HttpOnly 쿠키 저장
    /**
     * ✅ refreshToken을 HttpOnly 쿠키로 저장하는 이유
     * - JS에서 접근 불가 → XSS 위험 감소
     * - 브라우저가 자동으로 요청에 포함해줌
     *
     * ✅ 옵션 설명
     * - httpOnly: true
     * - secure: 운영환경(https)에서만 true
     * - sameSite: "lax" → 기본적인 CSRF 위험 완화
     * - path: "/" → 전체 경로에서 쿠키 사용
     * - maxAge: 실제 쿠키 수명(여기선 7일로 고정)
     */
    ctx.cookies.set(REFRESH_COOKIE_NAME, refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // 운영환경(https)에서만 none, 개발환경(http)에서는 lax
      path: "/",
      // REFRESH_TOKEN_EXPIRES와 맞춰서 대략 7일
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    /**
     * ✅ 최종 응답
     * - jwt: accessToken
     * - user: sanitizeUser로 보안 필드 제거한 안전한 유저 정보
     * - refreshToken은 "쿠키로만" 전달 (바디에 넣지 않음)
     */
    ctx.body = {
      jwt: accessToken,
      user: sanitizeUser(user),
    };
  },

  // ✅ refresh cookie로 access 재발급
  /**
   * ✅ refreshToken API 목적
   * - accessToken이 만료됐을 때
   * - refreshToken 쿠키가 살아있다면
   * - 새 accessToken을 발급해 "로그인 유지"를 가능하게 함
   */
  async refreshToken(ctx) {
    /**
     * ✅ 요청에 실려온 쿠키 중 refreshToken 읽기
     * - 브라우저/포스트맨이 자동으로 쿠키를 포함해야 함
     */
    const token = ctx.cookies.get(REFRESH_COOKIE_NAME);

    // ✅ 쿠키가 없으면 재발급 불가
    if (!token) {
      return ctx.unauthorized("refresh token 없음");
    }

    try {
      /**
       * ✅ refresh 토큰 검증
       * - 서명, 만료시간 체크
       * - 성공하면 payload를 얻음
       */
      const payload = jwt.verify(token, REFRESH_SECRET) as {
        id: number;
        type: string;
      };

      /**
       * ✅ type 검사
       * - access 토큰이나 다른 토큰을 refresh로 악용하는 걸 방지
       */
      if (payload.type !== "refresh") {
        return ctx.unauthorized("올바르지 않은 리프레시 토큰");
      }

      // 유저 재확인
      /**
       * ✅ 토큰이 유효해도
       * - 사용자가 실제 DB에 존재하는지 다시 체크
       * - 탈퇴/삭제된 유저라면 재발급 중단
       */
      const user = await strapi.db
        .query("plugin::users-permissions.user")
        .findOne({ where: { id: payload.id } });

      if (!user) {
        return ctx.unauthorized("유저가 존재하지 않습니다.");
      }

      // 새 access token
      /**
       * ✅ 새 accessToken 발급
       * - Strapi 기본 jwt.issue를 다시 사용
       * - refreshToken 자체는 여기서 다시 발급하지 않음(MVP 방식)
       */
      const newAccessToken =
        (strapi as any).plugins["users-permissions"].services.jwt.issue(
          { id: user.id },
          { expiresIn: ACCESS_EXPIRES_IN }
        );

      // ✅ 새 accessToken + 안전한 user 반환
      ctx.body = {
        jwt: newAccessToken,
        user: sanitizeUser(user),
      };
    } catch (e) {
      /**
       * ✅ verify 실패 케이스
       * - 만료됨
       * - 서명 불일치
       * - 토큰이 변조됨
       */
      return ctx.unauthorized("만료되었거나 유효하지 않은 리프레시 토큰");
    }
  },

  // ✅ (선택) 로그아웃: refresh 쿠키 삭제
  /**
   * ✅ logout API 목적
   * - 브라우저의 refreshToken 쿠키를 제거하여
   * - 더 이상 accessToken 재발급(자동 로그인 유지)이 불가능하게 만듦
   *
   * ✅ 참고
   * - 현재 방식은 "쿠키만 삭제하는 MVP 로그아웃"
   * - 보안을 더 강화하려면
   *   refreshToken을 DB에 저장하고 logout 시 서버에서도 폐기하는 방식으로 확장 가능
   */
  async logout(ctx) {
    /**
     * ✅ 동일 쿠키 이름에 빈 값을 세팅 + maxAge 0
     * - 브라우저에게 "이 쿠키 삭제해" 라고 명령하는 패턴
     */
    ctx.cookies.set(REFRESH_COOKIE_NAME, "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // 운영환경(https)에서만 none, 개발환경(http)에서는 lax
      path: "/",
      maxAge: 0,
    });

    // ✅ 프론트는 이 응답을 받으면 accessToken 상태도 함께 비우면 로그아웃 완성
    ctx.body = { ok: true };
  },
};


