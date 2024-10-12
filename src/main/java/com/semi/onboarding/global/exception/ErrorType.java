package com.semi.onboarding.global.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

@Getter
@AllArgsConstructor
public enum ErrorType {

    DUPLICATED_USERNAME(BAD_REQUEST, "이미 존재하는 아이디입니다."),
    REFRESH_TOKEN_INVALID(UNAUTHORIZED,"유효하지 않은 리프레시 토큰입니다."),
    NOT_FOUND_AUTHENTICATION_INFO(BAD_REQUEST, "인증에 실패하였습니다."),
    INVALID_JWT(BAD_REQUEST,"JWT 토큰 인증에 실패했습니다." )


    ;

    private final HttpStatus httpStatus;
    private final String message;
}
