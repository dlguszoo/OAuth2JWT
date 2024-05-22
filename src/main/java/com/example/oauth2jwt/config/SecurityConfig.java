package com.example.oauth2jwt.config;

import com.example.oauth2jwt.jwt.JWTFilter;
import com.example.oauth2jwt.jwt.JWTUtil;
import com.example.oauth2jwt.oauth2.CustomSuccessHandler;
import com.example.oauth2jwt.service.CustomOAuth2UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JWTUtil jwtUtil;

    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService, CustomSuccessHandler customSuccessHandler, JWTUtil jwtUtil) {
        this.customOAuth2UserService = customOAuth2UserService;
        this.customSuccessHandler = customSuccessHandler;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //CORS
        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() { //CorsConfigurationSource에 내부 CorsConfig값을 등록하는 방식

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000")); //프론트 주소
                        configuration.setAllowedMethods(Collections.singletonList("*")); //모든 요청에서 허용
                        configuration.setAllowCredentials(true); //credential값도 가져올 수 있도록 허용
                        configuration.setAllowedHeaders(Collections.singletonList("*")); //header값 설정
                        configuration.setMaxAge(3600L);

                        //우리쪽에서 data를 줄 경우, 웹 페이지에서 보일 수 있게 함: setExposedHeaders 설정
                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie")); //cookie를 반환할 것이기 때문에 Set-Cookie,
                        configuration.setExposedHeaders(Collections.singletonList("Authorization")); //Authorization 설정해야 jwt를 획득하고 받을 수 있다.

                        return configuration;
                    }
                }));

        //csrf disable
        http
                .csrf((auth) -> auth.disable());

        //From 로그인 방식 disable -> jwt,OAuth 방식 사용
        http
                .formLogin((auth) -> auth.disable());

        //HTTP Basic 인증 방식 disable -> jwt,OAuth 방식 사용
        http
                .httpBasic((auth) -> auth.disable());

        //JWTFilter 추가
        http
                .addFilterAfter(new JWTFilter(jwtUtil), OAuth2LoginAuthenticationFilter.class);

        //oauth2
        http
                .oauth2Login((oauth2) -> oauth2
                        .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig
                                .userService(customOAuth2UserService))
                        .successHandler(customSuccessHandler)
                );

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/").permitAll() // "/"만 모두 가능
                        .anyRequest().authenticated()); // 그 외에는 로그인한 유저만 접근 가능

        //세션 설정 : STATELESS
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
