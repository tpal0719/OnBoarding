package com.semi.onboarding.domain.user.controller;

import com.semi.onboarding.domain.user.dto.request.SignupRequestDto;
import com.semi.onboarding.domain.user.dto.response.SignupResponseDto;
import com.semi.onboarding.domain.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping
public class AuthController {

    private final UserService userService;

    @PostMapping("/signup")
    public SignupResponseDto signup(@Valid @RequestBody SignupRequestDto requestDto) {
        log.debug("signup request: {}", requestDto);
        return userService.signup(requestDto);
    }


}
