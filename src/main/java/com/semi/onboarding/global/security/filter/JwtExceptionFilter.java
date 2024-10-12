package com.semi.onboarding.global.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.semi.onboarding.global.dto.ErrorMessage;
import com.semi.onboarding.global.exception.CustomException;
import com.semi.onboarding.global.exception.ErrorType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtExceptionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            if(e instanceof CustomException customException){
                handleAuthenticationException(response, customException.getErrorType());
            }
        }
    }

    private void handleAuthenticationException(HttpServletResponse response, ErrorType errorType) throws IOException {
        response.setStatus(errorType.getHttpStatus().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(new ObjectMapper().writeValueAsString(ErrorMessage.builder()
                .statusCode(errorType.getHttpStatus().value())
                .message(errorType.getMessage())
                .build()
        ));
        response.getWriter().flush();
    }

}
