import jwt from "jsonwebtoken";

/**
 * refresh 토큰 서명/검증용 비밀키
 * - access 토큰은 Strapi 기본 jwt 서비스가 내부 secret 사용
 * - refresh 토큰은 우리가 직접 sign/verify 하므로 별도 secret 필요
 * - .env에 REFRESH_JWT_SECRET 설정 권장
 */
const REFRESH_SECRET = process.env.REFRESH_JWT_SECRET || "change-me";

/**
 * access 토큰 만료시간
 * - 기본값 15분
 * - Strapi jwt.issue 옵션으로 전달
 */
const ACCESS_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES || "15m";

/**
 * refresh 토큰 만료시간
 * - 기본값 7일
 * - jsonwebtoken.sign expiresIn에 사용
 */
const REFRESH_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES || "7d";

/**
 * refresh 토큰 쿠키 이름
 * - login / refresh / logout에서 동일하게 사용
 */
const REFRESH_COOKIE_NAME = "refreshToken";

/**
 * env의 expires 문자열(예: 15m, 7d)을 ms로 변환
 * - JWT 만료 시간과 쿠키 maxAge를 동일 기준으로 맞추기 위함
 */
function parseExpiresToMs(expires: string) {
  const match = expires.match(/^(\d+)([smhd])$/);
  if (!match) {
    throw new Error(`Invalid expires format: ${expires}`);
  }

  const value = Number(match[1]);
  const unit = match[2] as "s" | "m" | "h" | "d";

  const map = {
    s: 1000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
  };

  return value * map[unit];
}

const refreshMaxAge = parseExpiresToMs(REFRESH_EXPIRES_IN);

/**
 * user 객체에서 민감 정보 제거
 * - password
 * - resetPasswordToken
 * - confirmationToken
 * 프론트로 안전하게 전달하기 위한 필터
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
  /**
   * 로그인 + refresh 쿠키 발급
   *
   * 처리 흐름
   * 1) identifier + password 검증
   * 2) 사용자 조회
   * 3) 비밀번호 검증
   * 4) accessToken 발급
   * 5) refreshToken 발급
   * 6) refreshToken을 HttpOnly 쿠키로 저장
   * 7) accessToken + 안전한 user 반환
   */
  async customLogin(ctx) {
    // 🔎 HTTPS 판별 디버그 로그 (문제 해결 후 제거 예정)
    strapi.log.info(
      `HTTPS CHECK (login) protocol=${ctx.request.protocol} secure=${ctx.request.secure}`
    );

    /**
     * 로그인 요청 바디
     * - identifier: email 또는 username
     * - password: 비밀번호
     */
    const { identifier, password } = ctx.request.body as {
      identifier: string;
      password: string;
    };

    // 필수값 검사
    if (!identifier || !password) {
      return ctx.badRequest("identifier, password 필수");
    }

    /**
     * 사용자 조회
     * - email / username 둘 다 허용
     */
    const user = await strapi.db
      .query("plugin::users-permissions.user")
      .findOne({
        where: {
          $or: [{ email: identifier }, { username: identifier }],
        },
      });

    if (!user) {
      return ctx.unauthorized("잘못된 아이디/비밀번호입니다.");
    }

    /**
     * 비밀번호 검증
     * - Strapi 기본 validatePassword 사용
     */
    const validPassword =
      await (strapi as any).plugins["users-permissions"].services.user.validatePassword(
        password,
        user.password
      );

    if (!validPassword) {
      return ctx.unauthorized("잘못된 아이디/비밀번호입니다.");
    }

    /**
     * accessToken 발급
     * - 프론트 상태(Zustand 등)에 저장하는 용도
     */
    const accessToken =
      (strapi as any).plugins["users-permissions"].services.jwt.issue(
        { id: user.id },
        { expiresIn: ACCESS_EXPIRES_IN }
      );

    /**
     * refreshToken 발급
     * - payload에 type: "refresh" 포함
     * - refresh API에서 용도 검증 가능
     */
    const refreshToken = jwt.sign(
      { id: user.id, type: "refresh" },
      REFRESH_SECRET as string,
      { expiresIn: REFRESH_EXPIRES_IN as string | number } as jwt.SignOptions
    );

    /**
     * 실제 요청 기준 HTTPS 판별
     * - 프록시 환경에서 Strapi는 HTTP로 동작할 수 있음
     * - secure 쿠키를 강제로 true로 주면 에러 발생
     */
    const isHttps =
      ctx.request.protocol === "https" ||
      ctx.request.secure === true;

    /**
     * refreshToken을 HttpOnly 쿠키로 저장
     * - JS 접근 차단 (XSS 방어)
     * - sameSite / secure 값은 실제 요청 기준으로 결정
     * - 쿠키 만료 시간은 REFRESH_TOKEN_EXPIRES와 동기화
     */
    ctx.cookies.set(REFRESH_COOKIE_NAME, refreshToken, {
      httpOnly: true,
      secure: isHttps,
      sameSite: isHttps ? "none" : "lax",
      path: "/",
      maxAge: refreshMaxAge,
    });

    /**
     * 응답
     * - refreshToken은 쿠키로만 전달
     */
    ctx.body = {
      jwt: accessToken,
      user: sanitizeUser(user),
    };
  },

  /**
   * refreshToken 쿠키로 accessToken 재발급
   * - refreshToken 자체는 재발급하지 않음 (Fixed Session)
   */
  async refreshToken(ctx) {
    const token = ctx.cookies.get(REFRESH_COOKIE_NAME);

    if (!token) {
      return ctx.unauthorized("refresh token 없음");
    }

    try {
      const payload = jwt.verify(token, REFRESH_SECRET) as {
        id: number;
        type: string;
      };

      if (payload.type !== "refresh") {
        return ctx.unauthorized("올바르지 않은 리프레시 토큰");
      }

      const user = await strapi.db
        .query("plugin::users-permissions.user")
        .findOne({ where: { id: payload.id } });

      if (!user) {
        return ctx.unauthorized("유저가 존재하지 않습니다.");
      }

      const newAccessToken =
        (strapi as any).plugins["users-permissions"].services.jwt.issue(
          { id: user.id },
          { expiresIn: ACCESS_EXPIRES_IN }
        );

      ctx.body = {
        jwt: newAccessToken,
        user: sanitizeUser(user),
      };
    } catch {
      return ctx.unauthorized("만료되었거나 유효하지 않은 리프레시 토큰");
    }
  },

  /**
   * 로그아웃
   * - refreshToken 쿠키 삭제
   */
  async logout(ctx) {
    // 🔎 HTTPS 판별 디버그 로그 (문제 해결 후 제거 예정)
    strapi.log.info(
      `HTTPS CHECK (logout) protocol=${ctx.request.protocol} secure=${ctx.request.secure}`
    );

    /**
     * 실제 요청 기준 HTTPS 판별
     */
    const isHttps =
      ctx.request.protocol === "https" ||
      ctx.request.secure === true;

    /**
     * 동일 쿠키 이름 + 빈 값 + maxAge 0
     * → 브라우저에게 쿠키 삭제 지시
     */
    ctx.cookies.set(REFRESH_COOKIE_NAME, "", {
      httpOnly: true,
      secure: isHttps,
      sameSite: isHttps ? "none" : "lax",
      path: "/",
      maxAge: 0,
    });

    ctx.body = { ok: true };
  },
};
