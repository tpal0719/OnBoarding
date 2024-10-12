package com.semi.onboarding.global.exception;

public class UserException extends CustomException{
    public UserException(ErrorType errorType) {
        super(errorType);
    }
}
