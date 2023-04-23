package com.example.oauth2jwt.dto;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuthRequest {
    private String id;
    private String password;

    public AuthRequest(String id, String password) {
        this.id = id;
        this.password = password;
    }
}
