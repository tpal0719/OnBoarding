package com.semi.onboarding.domain.user.service;

import com.semi.onboarding.domain.user.dto.request.SignupRequestDto;
import com.semi.onboarding.domain.user.dto.response.SignupResponseDto;
import com.semi.onboarding.domain.user.entity.User;
import com.semi.onboarding.domain.user.entity.UserRole;
import com.semi.onboarding.domain.user.repository.UserRepository;
import com.semi.onboarding.global.exception.ErrorType;
import com.semi.onboarding.global.exception.UserException;
import com.semi.onboarding.global.security.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    // 회원가입
    @Transactional
    public SignupResponseDto signup(SignupRequestDto requestDto) {

        //중복검사
        String username = requestDto.getUsername();
        String password = requestDto.getPassword();

        Optional<User> checkUsername = userRepository.findByUsername(username);
        if (checkUsername.isPresent()) {
            throw new UserException(ErrorType.DUPLICATED_USERNAME);
        }
        //암호화
        String encodedPassword = passwordEncoder.encode(password);

        //생성 저장
        User newUser = new User(requestDto.getUsername(), encodedPassword, requestDto.getNickname(), UserRole.ROLE_USER);
        userRepository.save(newUser);

        UserDetailsImpl userDetails = new UserDetailsImpl(newUser);
        List<SignupResponseDto.Authority> authorities = userDetails.getAuthorities().stream()
                .map(authority -> new SignupResponseDto.Authority(authority.getAuthority()))
                .toList();
        return new SignupResponseDto(newUser.getUsername(),newUser.getNickname(),authorities);
    }

}
