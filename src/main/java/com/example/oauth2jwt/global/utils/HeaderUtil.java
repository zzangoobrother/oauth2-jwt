package com.example.oauth2jwt.global.utils;

import org.springframework.http.HttpHeaders;

import javax.servlet.http.HttpServletRequest;

public class HeaderUtil {
    private final static String TOKEN_PREFIX = "Bearer ";

    public static String getAccessToken(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorization == null) {
            return null;
        }

        if (authorization.startsWith(TOKEN_PREFIX)) {
            return authorization.substring(TOKEN_PREFIX.length());
        }

        return null;
    }
}
