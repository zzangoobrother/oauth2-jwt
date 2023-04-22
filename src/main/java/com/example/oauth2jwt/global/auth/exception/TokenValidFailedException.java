package com.example.oauth2jwt.global.auth.exception;

public class TokenValidFailedException extends RuntimeException {

    public TokenValidFailedException() {
        super("Failed to generate Token");
    }

    private TokenValidFailedException(String message) {
        super(message);
    }
}
