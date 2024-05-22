package com.example.oauth2jwt.oauth2;

import com.example.oauth2jwt.dto.CustomOAuth2User;
import com.example.oauth2jwt.jwt.JWTUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;

    public CustomSuccessHandler(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        //OAuth2User
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();

        String username = customUserDetails.getUsername(); //username값 받아오기

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority(); //role값 받아오기

        //JWT를 만들 때 username, role값을 넣어서 만듦
        String token = jwtUtil.createJwt(username, role, 60*60*60L);

        //JWT 전달해줄 방법: response에 cookie를 넣어줌
        response.addCookie(createCookie("Authorization", token));
        //프론트 측에 redirecting
        response.sendRedirect("http://localhost:3000/");


    }

    //cookie 만드는 메소드
    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        //cookie가 살아있을 시간
        cookie.setMaxAge(60*60*60);
        
        //cookie에 대해서 https통신에서만 사용할 수 있음
        //cookie.setSecure(true); //local 환경은 https가 아니기 때문에 주석처리
        
        //cookie가 보일 위치: 전역
        cookie.setPath("/");
        //JavaScript가 해당 쿠키를 가져가지 못하게 함
        cookie.setHttpOnly(true);

        return cookie;
    }
}
