package com.semi.onboarding.global.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

//    private final UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String accessToken = jwtUtil.getAccessTokenFromHeader(request);

        if(StringUtils.hasText(accessToken)){ // Access Token이 존재할 경우
            if(jwtUtil.validateTokenInternal(accessToken)){ // Access Token이 유효하면
                authenticateWithAccessToken(accessToken);  // 인증 수행
            } else {
                // accessToken이 유효하지 않을 때
                validateAndAuthenticateWithRefreshToken(request, response); // Access Token이 유효하지 않으면 Refresh Token 검증 및 재발급
            }
        }
        filterChain.doFilter(request, response);  // 필터 체인을 계속 실행
    }



    public void validateAndAuthenticate


}
