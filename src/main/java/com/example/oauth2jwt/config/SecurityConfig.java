package com.example.oauth2jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //csrf disable
        http
                .csrf((auth) -> auth.disable());

        //From 로그인 방식 disable -> jwt,OAuth 방식 사용
        http
                .formLogin((auth) -> auth.disable());

        //HTTP Basic 인증 방식 disable -> jwt,OAuth 방식 사용
        http
                .httpBasic((auth) -> auth.disable());

        //oauth2
        http
                .oauth2Login(Customizer.withDefaults()); //일단은 특정 커스텀 구현을 진행 X, 기본적인 default 설정해줌

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
