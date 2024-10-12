package com.semi.onboarding.domain.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
public class SignupResponseDto {

    private String username;
    private String nickname;
    private List<Authority> authorities;

    @Getter
    @AllArgsConstructor
    public static class Authority {
        private String authorityName;
    }

    public SignupResponseDto(String username, String nickname, List<Authority> authorities) {
        this.username = username;
        this.nickname = nickname;
        this.authorities = authorities;
    }

}
