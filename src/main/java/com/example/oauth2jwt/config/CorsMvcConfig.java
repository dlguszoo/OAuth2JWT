package com.example.oauth2jwt.config;

import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

public class CorsMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {
        corsRegistry.addMapping("/**") //특정한 모든 경로에서 매핑 진행
                .exposedHeaders("Set-Cookie") //노출할 header값: cookie header
                .allowedOrigins("http://localhost:3000"); //react와 같은 웹앱이 동작할 서버 주소를 넣어줌
    }
}
