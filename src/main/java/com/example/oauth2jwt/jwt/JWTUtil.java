package com.example.oauth2jwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {
    private SecretKey secretKey; //암호화 키 담기

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) { //@Value: application.properties에 담긴 특정한 변수값을 가져오기
        //String타입에서 UTF_8방식으로 인코딩하여 변환해서 넣어주기, JWT의존성 중 HS256 방식으로 암호화 진행
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    //밑의 3가지 메소드 다 토큰을 인자로 받아서 내부의 JWT 파서를 통해 토큰 payload에 담겨있는 특정값을 가지고 온다.

    public String getUsername(String token) { //username 확인

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) { //role 확인

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) { //토큰이 만료되었는지 확인

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createJwt(String username, String role, Long expiredMs) { //토큰 생성, expiredMs: 어느 정도 토큰이 살아 있을지의 기간

        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) //생성 시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) //만료 시간
                .signWith(secretKey)
                .compact();
    }
}
