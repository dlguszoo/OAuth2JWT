package com.example.oauth2jwt.jwt;

import com.example.oauth2jwt.dto.CustomOAuth2User;
import com.example.oauth2jwt.dto.UserDto;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil; //내부 cookie에서 jwt를 꺼내서 알맞은 토큰인지 검증과정을 거치기 때문에 주입받아야 함.

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //request에서 cookie들을 불러온 뒤 Authorization Key에 담긴 쿠키를 찾음
        String authorization = null;
        Cookie[] cookies = request.getCookies(); //불러온 쿠키들을 담음
        for (Cookie cookie : cookies) { //모든 쿠키를 순회해서

            if (cookie.getName().equals("Authorization")) { //Authorization이라는 Key에 담긴 쿠키

                authorization = cookie.getValue(); //value값을 담는다
            }
        }

        //Authorization 헤더 검증
        if (authorization == null) {

            System.out.println("token null");
            filterChain.doFilter(request, response); //다음 필터로 넘김

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        //토큰
        String token = authorization;

        //토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) {

            System.out.println("token expired");
            filterChain.doFilter(request, response); //다음 필터로 넘김

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        //토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        //userDTO를 생성하여 값 set
        UserDto userDTO = new UserDto();
        userDTO.setUsername(username);
        userDTO.setRole(role);

        //UserDetails에 userDTO 넘겨줘서 회원 정보 객체 생성
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);

        //생성한 객체를 UsernamePasswordAuthenticationToken에 담아냄. 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());
        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);
        
        filterChain.doFilter(request, response); //이 필터가 끝났으니, 다음 필터로 넘김
    }
}
