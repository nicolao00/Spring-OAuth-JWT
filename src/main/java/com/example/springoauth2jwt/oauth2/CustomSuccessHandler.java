package com.example.springoauth2jwt.oauth2;

import com.example.springoauth2jwt.dto.CustomOAuth2User;
import com.example.springoauth2jwt.jwt.JWTUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //OAuth2User
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

//        엑세스 토큰만 발행
//        String token = jwtUtil.createJwt(username, role, 60*60*60L);
//
//        response.addCookie(createCookie("Authorization", token));
//        response.sendRedirect("http://localhost:3000/");

        // 액세스, 리프레시 토큰 발행
        //토큰 생성
        String access = jwtUtil.createJwt("access", username, role, 600000L);
        String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        //응답 설정
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());
    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60*60*60);
        //cookie.setSecure(true); // 쿠키의 전송 경로를 설정. 기본적으로 "https"에서만 전송되도록 보안 옵션을 설정. https에서만 동작하도록 (지금은 http만 사용해서 주석처리)
        cookie.setPath("/"); // 쿠키의 전송 경로 설정. "/"는 모든 경로에서 쿠키가 전송되도록 설정하는 것. 즉, 해당 서버의 모든 페이지에서 쿠키를 사용할 수 있음.  쿠키가 보일(반환될) 위치. 일단 전역으로 선언
        cookie.setHttpOnly(true); // HttpOnly 설정: JavaScript에서 쿠키에 접근하지 못하게 하여 보안성을 높임.

        return cookie;
    }
}
