export default {
    routes: [
      {
        method: "POST",
        path: "/session/login",
        handler: "api::session.session.customLogin",
        config: { auth: false },
      },
      {
        method: "POST",
        path: "/session/refresh",
        handler: "api::session.session.refreshToken",
        config: { auth: false },
      },
      // (선택) 로그아웃도 같이 만들고 싶으면
      {
        method: "POST",
        path: "/session/logout",
        handler: "api::session.session.logout",
        config: { auth: false },
      },
    ],
  };