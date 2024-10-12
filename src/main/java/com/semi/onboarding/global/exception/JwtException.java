package com.semi.onboarding.global.exception;

import lombok.Getter;

@Getter
public class JwtException extends CustomException{

    public JwtException(ErrorType errorType) {
        super(errorType);
    }
}
