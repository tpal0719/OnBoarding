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


    public User(String username, String password,String nickname , UserRole userRole) {
        this.username = username;
        this.password = password;
        this.nickname = nickname;
        this.userRole = userRole;
    }

    public void saveRefreshToken(String refreshToken){
        this.refreshToken = refreshToken;
    }

    public boolean validateRefreshToken(String refreshToken){
        if(this.refreshToken != null && this.refreshToken.equals(refreshToken)){
            return true;
        }
        return false;
    }

    public void removeRefreshToken() {
        this.refreshToken = "";
    }

}
