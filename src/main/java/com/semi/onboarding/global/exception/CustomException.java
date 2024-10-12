package com.semi.onboarding.global.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public abstract class CustomException extends RuntimeException {
    private ErrorType errorType;
}
