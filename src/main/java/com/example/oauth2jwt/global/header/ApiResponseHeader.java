package com.example.oauth2jwt.global.header;

import lombok.Getter;

@Getter
public class ApiResponseHeader {
    private int code;
    private String message;

    public ApiResponseHeader(int code, String message) {
        this.code = code;
        this.message = message;
    }
}
