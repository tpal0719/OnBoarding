package com.semi.onboarding.domain.user.entity;

import com.semi.onboarding.global.entity.TimeStamped;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;


@Entity
@Getter
@Table(name = "users")
@NoArgsConstructor
public class User extends TimeStamped {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String nickname;

    private String password;

    private String refreshToken;

    @Enumerated(value = EnumType.STRING)
    private UserRole userRole;


    public User(String username, String nickname, String password, UserRole userRole) {
        this.username = username;
        this.nickname = nickname;
        this.password = password;
        this.userRole = userRole;
    }

}
