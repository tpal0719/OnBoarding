package com.semi.onboarding.global.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.semi.onboarding.domain.user.dto.request.LoginRequestDto;
import com.semi.onboarding.domain.user.entity.User;
import com.semi.onboarding.domain.user.entity.UserRole;
import com.semi.onboarding.domain.user.repository.UserRepository;
import com.semi.onboarding.global.dto.ErrorMessage;
import com.semi.onboarding.global.dto.ResponseMessage;
import com.semi.onboarding.global.exception.ErrorType;
import com.semi.onboarding.global.security.UserDetailsImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;

@Slf4j(topic = "로그인 및 JWT 생성")
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, UserRepository userRepository) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        setFilterProcessesUrl("/sign");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            LoginRequestDto requestDto = new ObjectMapper().readValue(request.getInputStream(), LoginRequestDto.class);

            return getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(
                            requestDto.getUsername(),
                            requestDto.getPassword(),
                            null
                    )
            );
        } catch (IOException e) {
            log.error(e.getMessage());
            throw new RuntimeException(e.getMessage());
        }
    }

    // 로그인 성공시 처리
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        User user = ((UserDetailsImpl) authResult.getPrincipal()).getUser();

        String username = ((UserDetailsImpl) authResult.getPrincipal()).getUsername();
        UserRole role = ((UserDetailsImpl) authResult.getPrincipal()).getUser().getUserRole();

        String accessToken = jwtUtil.createAccessToken(username, role);
        String refreshToken = jwtUtil.createRefreshToken(username, role);

        user.saveRefreshToken(refreshToken.substring(7));
        userRepository.save(user);

        response.addHeader(JwtUtil.AUTH_ACCESS_HEADER, accessToken);
        response.addHeader(JwtUtil.AUTH_REFRESH_HEADER, refreshToken);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        // JSON 형태로 token 값을 출력
        response.getWriter().write(new ObjectMapper().writeValueAsString(
                new HashMap<String, String>() {{
                    put("token", accessToken);
                }}
        ));

        response.getWriter().flush();
    }

    // 로그인 실패시 처리
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {
        ErrorType errorType = ErrorType.NOT_FOUND_AUTHENTICATION_INFO;
        response.setStatus(errorType.getHttpStatus().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(new ObjectMapper().writeValueAsString(ErrorMessage.<String>builder()
                .statusCode(errorType.getHttpStatus().value())
                .message(errorType.getMessage())
                .build())
        );
        response.getWriter().flush();
    }
}
