package com.semi.onboarding.global.jwt;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

import com.semi.onboarding.domain.user.entity.UserRole;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

@Component
@Slf4j(topic = "JwtUtil")
public class JwtUtil {

    // accessToken 토큰 헤더
    public static final String AUTH_ACCESS_HEADER = "Authorization";
    // refreshToken 토큰 헤더
    public static final String AUTH_REFRESH_HEADER = "RefreshToken";
    // 사용자 권한 키
    public static final String AUTHORIZATION_KEY = "auth";
    // Token 식별자
    public static final String BEARER_PREFIX = "Bearer ";
    // accessToken 만료 시간 (60분)
    private final long ACCESS_TOKEN_EXPIRE_TIME = 60 * 60 * 1000L;
    // refreshToken 만료 시간 (2주)
    private final long REFRESH_TOKEN_EXPIRE_TIME = 14 * 24 * 60 * 60 * 1000L;


    @Value("${jwt-secret-key}")
    private String secretKey;
    private Key key;
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @PostConstruct
    public void init(){
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        key = Keys.hmacShaKeyFor(bytes);
    }


    // accessToken 생성
    public String createAccessToken(String email) {

        Date date = new Date();
        return BEARER_PREFIX + Jwts.builder()
                .setSubject(email)   // 사용자 ID 설정
                .setExpiration(new Date(date.getTime() + ACCESS_TOKEN_EXPIRE_TIME))  // 만료 시간 설정
                .setIssuedAt(date)   // 발행 시간 설정
                .signWith(key, signatureAlgorithm)  // 키로 서명
                .compact();  // 토큰 생성
    }

    // accessToken 생성
    public String createAccessToken(String username, UserRole userRole) {
        Date date = new Date();

        return BEARER_PREFIX + Jwts.builder()
                .setSubject(username)
                .claim(AUTHORIZATION_KEY, userRole)
                .setExpiration(new Date(date.getTime() + ACCESS_TOKEN_EXPIRE_TIME))
                .setIssuedAt(date)
                .signWith(key, signatureAlgorithm)
                .compact();
    }

    // accessToken 생성
    public String createRefreshToken(String userId, UserRole role){
        Date date = new Date();

        return BEARER_PREFIX + Jwts.builder()
                .setSubject(userId)
                .claim(AUTHORIZATION_KEY, role)
                .setExpiration(new Date(date.getTime() + REFRESH_TOKEN_EXPIRE_TIME))
                .setIssuedAt(date)
                .signWith(key, signatureAlgorithm)
                .compact();
    }

    // 토큰을 HTTP 요청 헤더에서 가져오기
    // Bearer 로 시작하는 토큰만 유효한 것으로 간주하고, 접두어를 제거한 후 반환
    public String getAccessTokenFromHeader(HttpServletRequest request){
        String accessToken = request.getHeader(AUTH_ACCESS_HEADER);
        if (StringUtils.hasText(accessToken) && accessToken.startsWith(BEARER_PREFIX)) {
            return accessToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }


    // 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException | SignatureException e) {
            log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token, 만료된 JWT token 입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
        }
        return false;
    }




    // 토큰에서 사용자 정보 가져오기
    public Claims getUserInfoFromToken(String token){
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    // 응답 헤더에 accessToken 추가
    public void setHeaderAccessToken(HttpServletResponse response, String accessToken){
        response.setHeader(AUTH_ACCESS_HEADER, accessToken);
    }

}
